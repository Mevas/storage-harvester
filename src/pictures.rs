//! Pictures for the atlas.
//!
//! - `/api/thumb` makes a small JPEG of an image file, or of one frame of a video, with ffmpeg,
//!   for the targets that turn `thumbnails` on. It reads file contents, which nothing else in the
//!   harvester does.
//! - `/api/posters` and `/api/poster` show a Plex server's posters on the folders of its movie
//!   and show libraries (and their season folders).
//!
//! Each picture is made once and kept in `atlas.thumbnails.cache_dir`, keyed by what it shows:
//! a file's path, size, modification time and inode, or a poster's Plex URL (which changes when
//! the poster does). Making one that fails is remembered too, so it is not tried again.

use std::collections::HashMap;
use std::future::Future;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context};
use axum::body::Body;
use axum::http::{header, Request, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use serde_json::Value;
use tokio::sync::Semaphore;

use crate::config::{PlexConfig, ThumbnailConfig};

/// The widths pictures are made at; a request is rounded up to one of these.
pub const WIDTHS: [u32; 3] = [128, 256, 512];

pub fn width(asked: Option<&str>) -> u32 {
    let asked = asked
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(256);
    WIDTHS
        .iter()
        .copied()
        .find(|&width| width >= asked)
        .unwrap_or(WIDTHS[WIDTHS.len() - 1])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Image,
    Video,
}

const IMAGES: &[&str] = &[
    "jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff", "heic", "heif", "avif", "dng",
];
const VIDEOS: &[&str] = &[
    "mp4", "m4v", "mov", "mkv", "webm", "avi", "wmv", "mts", "m2ts", "3gp", "mpg", "mpeg", "flv",
];

/// Whether a file is an image or a video, by its extension.
pub fn kind_of(name: &str) -> Option<Kind> {
    let ext = name.rsplit_once('.')?.1.to_ascii_lowercase();
    if IMAGES.contains(&ext.as_str()) {
        Some(Kind::Image)
    } else if VIDEOS.contains(&ext.as_str()) {
        Some(Kind::Video)
    } else {
        None
    }
}

/// FNV-1a over `parts`, each one ended by a separator: stable across builds, so kept pictures
/// stay valid when the harvester is updated.
pub fn key(parts: &[&[u8]]) -> u64 {
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for &byte in *part {
            hash = (hash ^ u64::from(byte)).wrapping_mul(PRIME);
        }
        hash = (hash ^ 0xff).wrapping_mul(PRIME);
    }
    hash
}

/// What making a picture came to.
pub enum Made {
    Picture(Vec<u8>),
    /// There is no picture to make (an undecodable file, no poster): remembered.
    Nothing,
    /// Making it failed for now (a timeout, Plex unreachable): tried again next time.
    Failed,
}

/// Too many pictures waiting to be made, waited for too long, or making one failed for now: ask
/// again later.
pub struct Busy;

/// Requests waiting for a job slot beyond this are turned away at once.
const QUEUE_MAX: usize = 48;
/// How long a request waits for a job slot, and how long making the picture may take then (ffmpeg
/// and ffprobe killed past it): together within the relay's 30 s for an answer.
const QUEUE_WAIT: Duration = Duration::from_secs(8);
const MAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// ffmpeg's address space (Linux): a huge image fails instead of taking the container's memory.
/// A 4K HEVC frame took 423 MiB resident on the NAS (2026-11-06).
#[cfg(target_os = "linux")]
const FFMPEG_ADDRESS_SPACE: libc::rlim_t = 768 << 20;
/// A picture bigger than this is not one this module made.
const PICTURE_MAX: usize = 2 << 20;
/// Posters fetched from Plex at once.
const POSTER_FETCHES: usize = 4;

pub struct Pictures {
    cache: Arc<Cache>,
    ffmpeg: PathBuf,
    ffprobe: PathBuf,
    /// Whether ffmpeg answered at startup; without it no target makes thumbnails.
    pub ffmpeg_ok: bool,
    /// ffmpeg job slots: an image takes one, a video all of them (a 4K frame takes far more
    /// memory than a photo).
    jobs: Arc<Semaphore>,
    job_slots: u32,
    fetches: Arc<Semaphore>,
    queued: AtomicUsize,
    pub plex: Option<Arc<Plex>>,
}

impl Pictures {
    /// `thumbnails`: whether any target turns them on (ffmpeg is looked for only then).
    pub fn new(
        config: &ThumbnailConfig,
        plex: Option<&PlexConfig>,
        thumbnails: bool,
        client: Client<HttpConnector, Body>,
    ) -> Self {
        let ffmpeg_ok = thumbnails
            && std::process::Command::new(&config.ffmpeg)
                .arg("-version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success());
        if thumbnails && !ffmpeg_ok {
            tracing::warn!(
                ffmpeg = %config.ffmpeg.display(),
                "ffmpeg did not run: no thumbnails"
            );
        }
        let job_slots = u32::try_from(config.jobs).unwrap_or(u32::MAX).max(1);
        Self {
            cache: Arc::new(Cache {
                dir: config.cache_dir.clone(),
                max: config.cache_mib.saturating_mul(1 << 20),
                used: Mutex::new(None),
            }),
            ffmpeg: config.ffmpeg.clone(),
            ffprobe: config.ffprobe.clone(),
            ffmpeg_ok,
            jobs: Arc::new(Semaphore::new(job_slots as usize)),
            job_slots,
            fetches: Arc::new(Semaphore::new(POSTER_FETCHES)),
            queued: AtomicUsize::new(0),
            plex: plex.map(|config| {
                let plex = Arc::new(Plex::new(config, client));
                plex.start();
                plex
            }),
        }
    }

    /// The thumbnail under `key` of `file` (opened and checked by the caller), made now if it
    /// is not kept yet. `None`: there is none.
    pub async fn thumbnail(
        &self,
        key: u64,
        file: std::fs::File,
        kind: Kind,
        width: u32,
    ) -> Result<Option<Vec<u8>>, Busy> {
        let cost = match kind {
            Kind::Image => 1,
            Kind::Video => self.job_slots,
        };
        self.picture(key, &self.jobs, cost, || self.make(file, kind, width))
            .await
    }

    /// The poster under `key` of Plex's `thumb`, fetched now if it is not kept yet.
    pub async fn poster(&self, key: u64, thumb: &str, width: u32) -> Result<Option<Vec<u8>>, Busy> {
        let Some(plex) = &self.plex else {
            return Ok(None);
        };
        self.picture(key, &self.fetches, 1, || plex.fetch(thumb, width))
            .await
    }

    async fn picture<F, Fut>(
        &self,
        key: u64,
        slots: &Arc<Semaphore>,
        cost: u32,
        make: F,
    ) -> Result<Option<Vec<u8>>, Busy>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Made>,
    {
        if let Some(kept) = self.kept(key).await {
            return Ok(kept);
        }
        if self.queued.fetch_add(1, Ordering::SeqCst) >= QUEUE_MAX {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            return Err(Busy);
        }
        let slot =
            tokio::time::timeout(QUEUE_WAIT, Arc::clone(slots).acquire_many_owned(cost)).await;
        self.queued.fetch_sub(1, Ordering::SeqCst);
        let Ok(Ok(_slot)) = slot else {
            return Err(Busy);
        };
        // Another request may have made it while this one waited.
        if let Some(kept) = self.kept(key).await {
            return Ok(kept);
        }
        let made = match tokio::time::timeout(MAKE_TIMEOUT, make()).await {
            Ok(Made::Picture(bytes)) => Some(bytes),
            Ok(Made::Nothing) => None,
            Ok(Made::Failed) | Err(_) => return Err(Busy),
        };
        let cache = Arc::clone(&self.cache);
        let keep = made.clone();
        let _ = tokio::task::spawn_blocking(move || cache.put(key, keep.as_deref())).await;
        Ok(made)
    }

    async fn kept(&self, key: u64) -> Option<Option<Vec<u8>>> {
        let cache = Arc::clone(&self.cache);
        tokio::task::spawn_blocking(move || cache.get(key))
            .await
            .ok()
            .flatten()
    }

    /// A JPEG at least `width` on its short side: of an image, or of the key frame at or before
    /// 15% into a video (past black openings and titles, at most 90 s in), else its first one.
    async fn make(&self, file: std::fs::File, kind: Kind, width: u32) -> Made {
        let mut starts = vec![None];
        if kind == Kind::Video {
            let probe = [
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=nw=1:nk=1",
                "/dev/stdin",
            ];
            if let Run::Done(out) = run(&self.ffprobe, &probe, &file).await {
                let duration = String::from_utf8_lossy(&out).trim().parse::<f64>().ok();
                if let Some(duration) = duration.filter(|d| d.is_finite() && *d > 0.0) {
                    starts.insert(0, Some(format!("{:.2}", (duration * 0.15).min(90.0))));
                }
            }
        }
        // JPEG wants full-range YUV; video is usually limited-range.
        let scale = format!(
            "scale={width}:{width}:force_original_aspect_ratio=increase:force_divisible_by=2:out_range=full,format=yuvj420p"
        );
        let mut made = Made::Nothing;
        for start in &starts {
            let mut args = vec!["-hide_banner", "-v", "error", "-nostdin", "-threads", "2"];
            if let Some(start) = start {
                // The key frame at or before `start`: no decoding up to the exact time.
                args.extend(["-ss", start, "-noaccurate_seek"]);
            }
            // ffmpeg reads the file the harvester opened and checked, not a path that could be
            // swapped meanwhile; `/dev/stdin` opens it again, seekable.
            args.extend([
                "-i",
                "/dev/stdin",
                "-map",
                "0:v:0",
                "-frames:v",
                "1",
                "-vf",
                &scale,
            ]);
            args.extend(["-q:v", "6", "-f", "image2pipe", "-c:v", "mjpeg", "pipe:1"]);
            made = match run(&self.ffmpeg, &args, &file).await {
                Run::Done(out) if out.starts_with(&[0xff, 0xd8]) && out.len() <= PICTURE_MAX => {
                    return Made::Picture(out)
                }
                Run::Done(_) | Run::Refused => Made::Nothing,
                Run::Failed => Made::Failed,
            };
        }
        made
    }
}

enum Run {
    Done(Vec<u8>),
    /// The program ran and gave up on the file.
    Refused,
    /// It did not run.
    Failed,
}

/// Runs `program` at a low priority with `file` as its standard input, from the start.
async fn run(program: &Path, args: &[&str], file: &std::fs::File) -> Run {
    let input = file
        .try_clone()
        .and_then(|mut input| input.seek(SeekFrom::Start(0)).map(|_| input));
    let Ok(input) = input else {
        return Run::Failed;
    };
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::from(input))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // SAFETY: setpriority and setrlimit are async-signal-safe system calls.
    unsafe {
        command.pre_exec(|| {
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
            #[cfg(target_os = "linux")]
            {
                let limit = libc::rlimit {
                    rlim_cur: FFMPEG_ADDRESS_SPACE,
                    rlim_max: FFMPEG_ADDRESS_SPACE,
                };
                libc::setrlimit(libc::RLIMIT_AS, &limit);
            }
            Ok(())
        });
    }
    // Dropped at `MAKE_TIMEOUT`, which kills the program.
    match command.output().await {
        Ok(output) if output.status.success() => Run::Done(output.stdout),
        Ok(_) => Run::Refused,
        Err(failure) => {
            tracing::warn!(program = %program.display(), "cannot run: {failure}");
            Run::Failed
        }
    }
}

/// Pictures on disk, `<dir>/<first byte of key>/<key>.jpg`, and `<key>.none` for one there is
/// none of. Past `max` bytes the oldest go first, down to 80% of it.
struct Cache {
    dir: PathBuf,
    max: u64,
    /// Bytes held, measured on first use.
    used: Mutex<Option<u64>>,
}

impl Cache {
    fn path(&self, key: u64, ext: &str) -> PathBuf {
        self.dir
            .join(format!("{:02x}", key >> 56))
            .join(format!("{key:016x}.{ext}"))
    }

    /// `Some(Some(picture))`, `Some(None)` when there is none, `None` when not made yet.
    fn get(&self, key: u64) -> Option<Option<Vec<u8>>> {
        if let Ok(bytes) = std::fs::read(self.path(key, "jpg")) {
            return Some(Some(bytes));
        }
        self.path(key, "none").exists().then_some(None)
    }

    fn put(&self, key: u64, picture: Option<&[u8]>) {
        let (path, bytes) = match picture {
            Some(bytes) => (self.path(key, "jpg"), bytes),
            None => (self.path(key, "none"), &[][..]),
        };
        let Some(parent) = path.parent() else {
            return;
        };
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let partial = path.with_extension(format!(
            "part{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let written = std::fs::create_dir_all(parent)
            .and_then(|_| std::fs::write(&partial, bytes))
            .and_then(|_| std::fs::rename(&partial, &path));
        if let Err(failure) = written {
            let _ = std::fs::remove_file(&partial);
            tracing::warn!(path = %path.display(), "cannot keep a picture: {failure}");
            return;
        }
        let mut used = self.used.lock().unwrap_or_else(PoisonError::into_inner);
        let total = used.get_or_insert_with(|| self.entries().iter().map(|e| e.1).sum());
        *total += bytes.len() as u64;
        if *total > self.max {
            *total = self.evict();
        }
    }

    fn entries(&self) -> Vec<(SystemTime, u64, PathBuf)> {
        let mut entries = Vec::new();
        let Ok(shards) = std::fs::read_dir(&self.dir) else {
            return entries;
        };
        for shard in shards.flatten() {
            let Ok(files) = std::fs::read_dir(shard.path()) else {
                continue;
            };
            for file in files.flatten() {
                if let Ok(meta) = file.metadata() {
                    let made = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    entries.push((made, meta.len(), file.path()));
                }
            }
        }
        entries
    }

    /// Removes the oldest pictures until they take 80% of `max`; returns the bytes left.
    fn evict(&self) -> u64 {
        let mut entries = self.entries();
        entries.sort_unstable_by_key(|entry| entry.0);
        let mut total: u64 = entries.iter().map(|entry| entry.1).sum();
        for (_, size, path) in entries {
            if total <= self.max / 10 * 8 {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                total -= size;
            }
        }
        total
    }
}

/// How often Plex's libraries are read again, and how soon after a failed read.
const PLEX_REFRESH: Duration = Duration::from_secs(15 * 60);
const PLEX_RETRY: Duration = Duration::from_secs(60);
const PLEX_TIMEOUT: Duration = Duration::from_secs(30);
/// Shows whose folders one request asks for.
const PLEX_BATCH: usize = 50;

pub struct Plex {
    url: String,
    token: Option<String>,
    /// `(Plex's path, this harvester's)`, longest first.
    paths: Vec<(String, String)>,
    client: Client<HttpConnector, Body>,
    /// Folder (as this harvester shows it) → Plex's poster URL path, as last read; `None` before
    /// the first read.
    posters: RwLock<Option<Arc<HashMap<String, String>>>>,
}

impl Plex {
    fn new(config: &PlexConfig, client: Client<HttpConnector, Body>) -> Self {
        let token = std::env::var(&config.token_env)
            .ok()
            .filter(|token| !token.is_empty());
        if token.is_none() {
            tracing::warn!(
                env = %config.token_env,
                "no Plex token: Plex may refuse to list its libraries"
            );
        }
        let mut paths: Vec<(String, String)> = config
            .paths
            .iter()
            .map(|(from, to)| {
                let trim = |p: &str| p.trim_end_matches('/').to_string();
                (trim(from), trim(to))
            })
            .collect();
        paths.sort_by_key(|(from, _)| std::cmp::Reverse(from.len()));
        Self {
            url: config.url.trim_end_matches('/').to_string(),
            token,
            paths,
            client,
            posters: RwLock::new(None),
        }
    }

    /// Reads Plex's libraries now and every `PLEX_REFRESH` after (`PLEX_RETRY` after a failure),
    /// in the background: a request never waits for Plex's libraries.
    fn start(self: &Arc<Self>) {
        let plex = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                let next = match plex.read().await {
                    Ok(posters) => {
                        *plex.posters.write().unwrap_or_else(PoisonError::into_inner) =
                            Some(Arc::new(posters));
                        PLEX_REFRESH
                    }
                    Err(failure) => {
                        tracing::warn!("cannot read Plex's libraries: {failure:#}");
                        PLEX_RETRY
                    }
                };
                tokio::time::sleep(next).await;
            }
        });
    }

    /// Whether Plex's libraries can hold folders inside `path` (a target's).
    pub fn covers(&self, path: &Path) -> bool {
        self.paths
            .iter()
            .any(|(_, to)| Path::new(to).starts_with(path) || path.starts_with(to))
    }

    /// Folders with a poster, as last read from Plex; `None` before the first read.
    pub fn posters(&self) -> Option<Arc<HashMap<String, String>>> {
        self.posters
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Plex's path as this harvester shows it.
    fn shown(&self, plex: &str) -> Option<String> {
        self.paths.iter().find_map(|(from, to)| {
            let rest = plex.strip_prefix(from.as_str())?;
            (rest.is_empty() || rest.starts_with('/')).then(|| format!("{to}{rest}"))
        })
    }

    async fn read(&self) -> anyhow::Result<HashMap<String, String>> {
        let mut posters = HashMap::new();
        let sections = self.json("/library/sections").await?;
        for section in items(&sections, "Directory") {
            let Some(key) = section["key"].as_str() else {
                continue;
            };
            let mapped = items(section, "Location").any(|location| {
                location["path"]
                    .as_str()
                    .and_then(|p| self.shown(p))
                    .is_some()
            });
            if !mapped {
                continue;
            }
            match section["type"].as_str() {
                Some("movie") => self.movies(key, &mut posters).await?,
                Some("show") => self.shows(key, &mut posters).await?,
                _ => {}
            }
        }
        Ok(posters)
    }

    /// A movie's poster goes on the folder its file is in.
    async fn movies(
        &self,
        section: &str,
        posters: &mut HashMap<String, String>,
    ) -> anyhow::Result<()> {
        let all = self
            .json(&format!("/library/sections/{section}/all?type=1"))
            .await?;
        for movie in items(&all, "Metadata") {
            let Some(thumb) = movie["thumb"].as_str() else {
                continue;
            };
            for media in items(movie, "Media") {
                for part in items(media, "Part") {
                    let folder = part["file"]
                        .as_str()
                        .and_then(|file| file.rsplit_once('/'))
                        .and_then(|(folder, _)| self.shown(folder));
                    if let Some(folder) = folder {
                        posters.entry(folder).or_insert_with(|| thumb.to_string());
                    }
                }
            }
        }
        Ok(())
    }

    /// A show's poster goes on its folders, and each season's on `Season 01` (or `Season 1`,
    /// `Specials` for season 0) inside them: the show's again when a season has none of its own.
    async fn shows(
        &self,
        section: &str,
        posters: &mut HashMap<String, String>,
    ) -> anyhow::Result<()> {
        let all = self
            .json(&format!("/library/sections/{section}/all?type=2"))
            .await?;
        let keys: Vec<&str> = items(&all, "Metadata")
            .filter_map(|show| show["ratingKey"].as_str())
            .collect();
        // Show → its poster and its folders.
        let mut shows_at: HashMap<String, (String, Vec<String>)> = HashMap::new();
        for batch in keys.chunks(PLEX_BATCH) {
            let shows = self
                .json(&format!("/library/metadata/{}", batch.join(",")))
                .await?;
            for show in items(&shows, "Metadata") {
                let (Some(key), Some(thumb)) = (show["ratingKey"].as_str(), show["thumb"].as_str())
                else {
                    continue;
                };
                for location in items(show, "Location") {
                    if let Some(folder) = location["path"].as_str().and_then(|p| self.shown(p)) {
                        posters
                            .entry(folder.clone())
                            .or_insert_with(|| thumb.to_string());
                        let entry = shows_at
                            .entry(key.to_string())
                            .or_insert_with(|| (thumb.to_string(), Vec::new()));
                        entry.1.push(folder);
                    }
                }
            }
        }
        let seasons = self
            .json(&format!("/library/sections/{section}/all?type=3"))
            .await?;
        for season in items(&seasons, "Metadata") {
            let (Some(show), Some(index)) =
                (season["parentRatingKey"].as_str(), season["index"].as_u64())
            else {
                continue;
            };
            let Some((show_thumb, folders)) = shows_at.get(show) else {
                continue;
            };
            let thumb = season["thumb"].as_str().unwrap_or(show_thumb);
            let mut names = vec![format!("Season {index:02}"), format!("Season {index}")];
            if index == 0 {
                names.push("Specials".to_string());
            }
            for folder in folders {
                for name in &names {
                    posters
                        .entry(format!("{folder}/{name}"))
                        .or_insert_with(|| thumb.to_string());
                }
            }
        }
        Ok(())
    }

    async fn json(&self, path: &str) -> anyhow::Result<Value> {
        let (status, _, body) = self.get(path, "application/json", 64 << 20).await?;
        if status != StatusCode::OK {
            bail!("{path}: HTTP {status}");
        }
        serde_json::from_slice(&body).with_context(|| format!("{path}: not JSON"))
    }

    /// Plex's poster at `thumb`, scaled by Plex to `width` across.
    async fn fetch(&self, thumb: &str, width: u32) -> Made {
        let path = format!(
            "/photo/:/transcode?width={width}&height={}&minSize=1&upscale=1&url={}",
            width * 3 / 2,
            encode(thumb)
        );
        match self.get(&path, "image/jpeg", PICTURE_MAX).await {
            Ok((StatusCode::OK, kind, body)) if kind.starts_with("image/") => Made::Picture(body),
            Ok((StatusCode::NOT_FOUND, _, _)) => Made::Nothing,
            Ok((status, _, _)) => {
                tracing::warn!(%status, "Plex did not send a poster");
                Made::Failed
            }
            Err(failure) => {
                tracing::warn!("cannot fetch a poster from Plex: {failure:#}");
                Made::Failed
            }
        }
    }

    async fn get(
        &self,
        path: &str,
        accept: &str,
        limit: usize,
    ) -> anyhow::Result<(StatusCode, String, Vec<u8>)> {
        let uri: Uri = format!("{}{path}", self.url).parse()?;
        let mut request = Request::get(uri).header(header::ACCEPT, accept);
        if let Some(token) = &self.token {
            request = request.header("X-Plex-Token", token);
        }
        let request = request.body(Body::empty())?;
        let answer = async {
            let response = self.client.request(request).await?;
            let status = response.status();
            let kind = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = axum::body::to_bytes(Body::new(response.into_body()), limit).await?;
            anyhow::Ok((status, kind, body.to_vec()))
        };
        tokio::time::timeout(PLEX_TIMEOUT, answer)
            .await
            .context("Plex did not answer in time")?
    }
}

/// `value["MediaContainer"][field]` (or `value[field]`) as a list.
fn items<'a>(value: &'a Value, field: &str) -> impl Iterator<Item = &'a Value> {
    let inner = value.get("MediaContainer").unwrap_or(value);
    inner[field].as_array().into_iter().flatten()
}

/// Percent-encodes everything but unreserved characters and `/`, for a query value.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_round_up_to_the_sizes_made() {
        assert_eq!(width(None), 256);
        assert_eq!(width(Some("90")), 128);
        assert_eq!(width(Some("129")), 256);
        assert_eq!(width(Some("4000")), 512);
        assert_eq!(width(Some("x")), 256);
    }

    #[test]
    fn kinds_come_from_the_extension() {
        assert_eq!(kind_of("IMG_0001.JPG"), Some(Kind::Image));
        assert_eq!(kind_of("raw.dng"), Some(Kind::Image));
        assert_eq!(kind_of("clip.MP4"), Some(Kind::Video));
        assert_eq!(kind_of("notes.nfo"), None);
        assert_eq!(kind_of("jpg"), None);
    }

    #[test]
    fn keys_differ_by_part_not_just_by_bytes() {
        assert_ne!(key(&[b"ab", b"c"]), key(&[b"a", b"bc"]));
        assert_eq!(key(&[b"ab", b"c"]), key(&[b"ab", b"c"]));
    }

    #[test]
    fn plex_paths_map_to_the_harvesters() {
        let config = PlexConfig {
            url: "http://plex:32400".into(),
            token_env: "STORAGE_HARVESTER_TEST_NO_TOKEN".into(),
            paths: [
                (
                    "/data/media/".to_string(),
                    "/volume1/data/media".to_string(),
                ),
                ("/data".to_string(), "/elsewhere".to_string()),
            ]
            .into(),
        };
        let client =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());
        let plex = Plex::new(&config, client);
        assert_eq!(
            plex.shown("/data/media/anime/Show").as_deref(),
            Some("/volume1/data/media/anime/Show")
        );
        assert_eq!(
            plex.shown("/data/media").as_deref(),
            Some("/volume1/data/media")
        );
        assert_eq!(
            plex.shown("/data/mediax").as_deref(),
            Some("/elsewhere/mediax")
        );
        assert_eq!(plex.shown("/other"), None);
        assert!(plex.covers(Path::new("/volume1/data")));
        assert!(plex.covers(Path::new("/volume1/data/media/anime")));
        assert!(!plex.covers(Path::new("/volume1/homes")));
    }

    #[test]
    fn query_values_are_encoded() {
        assert_eq!(
            encode("/library/metadata/1/thumb/2?a=b c"),
            "/library/metadata/1/thumb/2%3Fa%3Db%20c"
        );
    }

    #[test]
    fn the_cache_keeps_pictures_and_misses_and_drops_the_oldest() {
        let dir = tempfile::tempdir().unwrap();
        let cache = Cache {
            dir: dir.path().to_path_buf(),
            max: 10_000,
            used: Mutex::new(None),
        };
        assert_eq!(cache.get(1), None);
        cache.put(1, Some(&[1; 4000]));
        cache.put(2, None);
        assert_eq!(cache.get(1).unwrap().unwrap().len(), 4000);
        assert_eq!(cache.get(2), Some(None));
        // Make key 1 the oldest, then go past the limit: it goes first.
        let old = std::fs::File::options()
            .write(true)
            .open(cache.path(1, "jpg"))
            .unwrap();
        old.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
            .unwrap();
        cache.put(3, Some(&[3; 4000]));
        cache.put(4, Some(&[4; 4000]));
        assert_eq!(cache.get(1), None);
        assert!(cache.get(3).is_some() && cache.get(4).is_some());
    }
}
