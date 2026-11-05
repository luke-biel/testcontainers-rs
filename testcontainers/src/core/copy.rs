use std::path::{Path, PathBuf};

use async_trait::async_trait;
use tar_framing::{
    header::{CHECKSUM_RANGE, MODE_RANGE},
    write::{end_marker_bytes, frame_pax_member_into, payload_padding, PaxMember},
    UstarKind,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone)]
pub struct CopyToContainerCollection(Vec<CopyToContainer>);

#[derive(Debug, Clone)]
pub struct CopyToContainer {
    target: CopyTargetOptions,
    source: CopyDataSource,
}

#[derive(Debug, Clone)]
pub struct CopyTargetOptions {
    target: String,
    mode: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum CopyDataSource {
    File(PathBuf),
    Data(Vec<u8>),
}

/// Errors that can occur while materializing data copied from a container.
#[derive(Debug, thiserror::Error)]
pub enum CopyFromContainerError {
    #[error("io failed with error: {0}")]
    Io(#[from] std::io::Error),
    #[error("archive did not contain any regular files")]
    EmptyArchive,
    #[error("requested container path is a directory")]
    IsDirectory,
    #[error("archive entry type '{0:?}' is not supported for requested target")]
    UnsupportedEntry(UstarKind),
}

/// Abstraction for materializing the bytes read from a source into a concrete destination.
///
/// Implementors typically persist the incoming bytes to disk or buffer them in memory. Some return
/// a value that callers can work with (for example, the collected bytes), while others simply
/// report success with `()`. Implementations must consume the provided reader until EOF or return
/// an error. Destinations are allowed to discard any existing data to make room for the incoming
/// bytes.
#[async_trait(?Send)]
pub trait CopyFileFromContainer {
    type Output;

    /// Writes all bytes from the reader into `self`, returning a value that represents the completed operation (or `()` for sinks that only confirm success).
    ///
    /// Implementations may mutate `self` and must propagate I/O errors via [`CopyFromContainerError`].
    async fn copy_from_reader<R>(self, reader: R) -> Result<Self::Output, CopyFromContainerError>
    where
        R: AsyncRead + Unpin;
}

#[async_trait(?Send)]
impl CopyFileFromContainer for Vec<u8> {
    type Output = Vec<u8>;

    async fn copy_from_reader<R>(
        mut self,
        reader: R,
    ) -> Result<Self::Output, CopyFromContainerError>
    where
        R: AsyncRead + Unpin,
    {
        let mut_ref = &mut self;
        mut_ref.copy_from_reader(reader).await?;
        Ok(self)
    }
}

#[async_trait(?Send)]
impl CopyFileFromContainer for &mut Vec<u8> {
    type Output = ();

    async fn copy_from_reader<R>(
        mut self,
        mut reader: R,
    ) -> Result<Self::Output, CopyFromContainerError>
    where
        R: AsyncRead + Unpin,
    {
        self.clear();
        reader
            .read_to_end(&mut self)
            .await
            .map_err(CopyFromContainerError::Io)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl CopyFileFromContainer for PathBuf {
    type Output = ();

    async fn copy_from_reader<R>(self, reader: R) -> Result<Self::Output, CopyFromContainerError>
    where
        R: AsyncRead + Unpin,
    {
        self.as_path().copy_from_reader(reader).await
    }
}

#[async_trait(?Send)]
impl CopyFileFromContainer for &Path {
    type Output = ();

    async fn copy_from_reader<R>(
        self,
        mut reader: R,
    ) -> Result<Self::Output, CopyFromContainerError>
    where
        R: AsyncRead + Unpin,
    {
        if let Some(parent) = self.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(CopyFromContainerError::Io)?;
            }
        }

        let mut file = tokio::fs::File::create(self)
            .await
            .map_err(CopyFromContainerError::Io)?;

        tokio::io::copy(&mut reader, &mut file)
            .await
            .map_err(CopyFromContainerError::Io)?;

        file.flush().await.map_err(CopyFromContainerError::Io)?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CopyToContainerError {
    #[error("io failed with error: {0}")]
    IoError(std::io::Error),
    #[error("failed to get the path name: {0}")]
    PathNameError(String),
}

fn append_tar_header(
    ar: &mut Vec<u8>,
    path: &str,
    kind: UstarKind,
    size: u64,
    mode: u32,
) -> Result<(), CopyToContainerError> {
    let mut framing = Vec::new();
    // Each member's byte offset supplies a unique sequence for its pax header name.
    frame_pax_member_into(
        ar.len() as u64,
        PaxMember {
            path,
            kind,
            size,
            link_path: None,
            executable: mode & 0o111 != 0,
        },
        &mut framing,
    )
    .map_err(|error| CopyToContainerError::IoError(std::io::Error::other(error)))?;

    // astral-codec currently encodes executable intent only. Restore the full mode
    // on the ordinary header (the final block of this member's pax framing).
    let header_start = framing.len() - tar_framing::BLOCK_SIZE;
    let header = &mut framing[header_start..];
    let mode = format!("{:07o}\0", mode & 0o7777);
    header[MODE_RANGE].copy_from_slice(mode.as_bytes());
    header[CHECKSUM_RANGE].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[CHECKSUM_RANGE].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    ar.extend_from_slice(&framing);
    Ok(())
}

impl CopyToContainerCollection {
    pub fn new(collection: Vec<CopyToContainer>) -> Self {
        Self(collection)
    }

    pub fn add(&mut self, entry: CopyToContainer) {
        self.0.push(entry);
    }

    pub(crate) async fn tar(&self) -> Result<bytes::Bytes, CopyToContainerError> {
        let mut ar = Vec::new();
        // BuildKit detects tar contexts from their first 1024 bytes. Start with a
        // plain ustar directory header so detection need not read past a pax extension.
        append_tar_header(&mut ar, ".", UstarKind::Directory, 0, 0o755)?;
        let header_start = ar.len() - tar_framing::BLOCK_SIZE;
        ar.drain(..header_start);
        for entry in &self.0 {
            entry.append_tar(&mut ar).await?;
        }
        ar.extend_from_slice(end_marker_bytes());
        Ok(ar.into())
    }
}

impl CopyToContainer {
    pub fn new(source: impl Into<CopyDataSource>, target: impl Into<CopyTargetOptions>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
        }
    }

    pub(crate) async fn tar(&self) -> Result<bytes::Bytes, CopyToContainerError> {
        let mut ar = Vec::new();
        self.append_tar(&mut ar).await?;
        ar.extend_from_slice(end_marker_bytes());
        Ok(ar.into())
    }

    async fn append_tar(&self, ar: &mut Vec<u8>) -> Result<(), CopyToContainerError> {
        self.source.append_tar(ar, &self.target).await
    }
}

impl CopyTargetOptions {
    pub fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            mode: None,
        }
    }

    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn mode(&self) -> Option<u32> {
        self.mode
    }
}

impl<T> From<T> for CopyTargetOptions
where
    T: Into<String>,
{
    fn from(value: T) -> Self {
        CopyTargetOptions::new(value.into())
    }
}

impl From<&Path> for CopyDataSource {
    fn from(value: &Path) -> Self {
        CopyDataSource::File(value.to_path_buf())
    }
}

impl From<PathBuf> for CopyDataSource {
    fn from(value: PathBuf) -> Self {
        CopyDataSource::File(value)
    }
}
impl From<Vec<u8>> for CopyDataSource {
    fn from(value: Vec<u8>) -> Self {
        CopyDataSource::Data(value)
    }
}

impl CopyDataSource {
    async fn append_tar(
        &self,
        ar: &mut Vec<u8>,
        target: &CopyTargetOptions,
    ) -> Result<(), CopyToContainerError> {
        let target_path = target.target();

        match self {
            CopyDataSource::File(source_file_path) => {
                if let Err(e) = append_tar_file(ar, source_file_path, target).await {
                    log::error!(
                        "Could not append file/dir to tar: {source_file_path:?}:{target_path}"
                    );
                    return Err(e);
                }
            }
            CopyDataSource::Data(data) => {
                if let Err(e) = append_tar_bytes(ar, data, target) {
                    log::error!("Could not append data to tar: {target_path}");
                    return Err(e);
                }
            }
        };

        Ok(())
    }
}

async fn append_tar_file(
    ar: &mut Vec<u8>,
    source_file_path: &Path,
    target: &CopyTargetOptions,
) -> Result<(), CopyToContainerError> {
    let mut pending = vec![(
        source_file_path.to_path_buf(),
        make_path_relative(target.target()),
        target.mode(),
    )];
    while let Some((source, path, mode_override)) = pending.pop() {
        let meta = tokio::fs::metadata(&source)
            .await
            .map_err(CopyToContainerError::IoError)?;
        let mode_override = if meta.is_dir() { None } else { mode_override };
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            mode_override.unwrap_or_else(|| meta.permissions().mode())
        };
        #[cfg(not(unix))]
        let mode = mode_override.unwrap_or(if meta.is_dir() { 0o755 } else { 0o644 });

        if meta.is_dir() {
            if !path.is_empty() {
                append_tar_header(ar, &path, UstarKind::Directory, 0, mode)?;
            }
            let mut entries = tokio::fs::read_dir(&source)
                .await
                .map_err(CopyToContainerError::IoError)?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(CopyToContainerError::IoError)?
            {
                let name = entry.file_name().into_string().map_err(|name| {
                    CopyToContainerError::PathNameError(name.to_string_lossy().into_owned())
                })?;
                let child_path = if path.is_empty() {
                    name
                } else {
                    format!("{path}/{name}")
                };
                pending.push((entry.path(), child_path, None));
            }
        } else if meta.is_file() {
            let file = tokio::fs::File::open(&source)
                .await
                .map_err(CopyToContainerError::IoError)?;
            append_tar_header(ar, &path, UstarKind::Regular, meta.len(), mode)?;
            let copied = tokio::io::copy(&mut file.take(meta.len()), ar)
                .await
                .map_err(CopyToContainerError::IoError)?;
            if copied != meta.len() {
                return Err(CopyToContainerError::IoError(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "archive source file is truncated",
                )));
            }
            ar.extend_from_slice(payload_padding(meta.len()));
        } else {
            return Err(CopyToContainerError::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "archive source is not a regular file or directory",
            )));
        }
    }
    Ok(())
}

fn append_tar_bytes(
    ar: &mut Vec<u8>,
    data: &[u8],
    target: &CopyTargetOptions,
) -> Result<(), CopyToContainerError> {
    append_tar_header(
        ar,
        &make_path_relative(target.target()),
        UstarKind::Regular,
        data.len() as u64,
        target.mode().unwrap_or(0o644),
    )?;
    ar.extend_from_slice(data);
    ar.extend_from_slice(payload_padding(data.len() as u64));
    Ok(())
}

fn make_path_relative(path: &str) -> String {
    // TODO support also absolute windows paths like "C:\temp\foo.txt"
    if path.starts_with("/") {
        path.trim_start_matches("/").to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Write};

    use tar_framing::logical::TarReader;
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn copytocontainer_tar_file_success() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "TEST").unwrap();

        let copy_to_container = CopyToContainer::new(file_path, "file.txt");
        let result = copy_to_container.tar().await;

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[tokio::test]
    async fn copytocontainer_tar_data_success() {
        let data = vec![1, 2, 3, 4, 5];
        let copy_to_container = CopyToContainer::new(data, "data.bin");
        let result = copy_to_container.tar().await;

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[tokio::test]
    async fn copytocontainer_tar_file_not_found() {
        let temp_dir = tempdir().unwrap();
        let non_existent_file_path = temp_dir.path().join("non_existent_file.txt");

        let copy_to_container = CopyToContainer::new(non_existent_file_path, "file.txt");
        let result = copy_to_container.tar().await;

        assert!(result.is_err());
        if let Err(CopyToContainerError::IoError(err)) = result {
            assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        } else {
            panic!("Expected IoError");
        }
    }

    #[tokio::test]
    async fn copytocontainercollection_tar_file_and_data() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "TEST").unwrap();

        let copy_to_container_collection = CopyToContainerCollection::new(vec![
            CopyToContainer::new(file_path, "file.txt"),
            CopyToContainer::new(vec![1, 2, 3, 4, 5], "data.bin"),
        ]);

        let result = copy_to_container_collection.tar().await;

        assert!(result.is_ok());
        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[tokio::test]
    async fn tar_bytes_respects_custom_mode() {
        let data = vec![1, 2, 3];
        let target = CopyTargetOptions::new("data.bin").with_mode(0o600);
        let copy_to_container = CopyToContainer::new(data, target);

        let tar_bytes = copy_to_container.tar().await.unwrap();
        let mut archive = TarReader::new(std::io::Cursor::new(tar_bytes));
        let entry = archive.next_frame().await.unwrap().unwrap();

        assert_eq!(entry.header.mode.unwrap(), 0o600);
    }

    #[tokio::test]
    async fn tar_file_respects_custom_mode() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "TEST").unwrap();

        let target = CopyTargetOptions::new("file.txt").with_mode(0o640);
        let copy_to_container = CopyToContainer::new(file_path, target);

        let tar_bytes = copy_to_container.tar().await.unwrap();
        let mut archive = TarReader::new(std::io::Cursor::new(tar_bytes));
        let entry = archive.next_frame().await.unwrap().unwrap();

        assert_eq!(entry.header.mode.unwrap(), 0o640);
    }
}
