//! SMB2 info response builders.
//!
//! These functions build binary response buffers for QUERY_INFO and QUERY_DIRECTORY
//! commands according to MS-SMB2 specifications.

use super::time::current_filetime;
use rustsmb_vfs::FileType;

/// Build directory info buffer from entries.
///
/// Builds FileBothDirectoryInformation structures per MS-SMB2 2.4.8.
pub fn build_directory_info(entries: &[rustsmb_vfs::DirEntry]) -> Vec<u8> {
    let mut buf = Vec::new();

    for (i, entry) in entries.iter().enumerate() {
        let name_bytes: Vec<u16> = entry.name.encode_utf16().collect();
        let name_len = name_bytes.len() * 2;

        // FileBothDirectoryInformation structure
        let entry_size = 94 + name_len; // Fixed fields + name
        let next_offset = if i < entries.len() - 1 {
            // Align to 8 bytes
            (entry_size + 7) & !7
        } else {
            0
        };

        buf.extend_from_slice(&(next_offset as u32).to_le_bytes()); // NextEntryOffset
        buf.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // CreationTime
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastAccessTime
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastWriteTime
        buf.extend_from_slice(&current_filetime().to_le_bytes()); // ChangeTime
        buf.extend_from_slice(&entry.metadata.size.to_le_bytes()); // EndOfFile
        buf.extend_from_slice(&entry.metadata.size.to_le_bytes()); // AllocationSize

        let is_dir = entry.metadata.file_type == FileType::Directory;
        let attrs = if is_dir { 0x10u32 } else { 0x80u32 }; // Directory or Normal
        buf.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
        buf.extend_from_slice(&(name_len as u32).to_le_bytes()); // FileNameLength
        buf.extend_from_slice(&0u32.to_le_bytes()); // EaSize
        buf.push(0); // ShortNameLength
        buf.push(0); // Reserved
        buf.extend_from_slice(&[0u8; 24]); // ShortName (12 UTF-16 chars)

        // FileName
        for c in name_bytes {
            buf.extend_from_slice(&c.to_le_bytes());
        }

        // Padding to 8-byte alignment
        if next_offset > 0 {
            let padding = next_offset - entry_size;
            buf.extend(std::iter::repeat(0u8).take(padding));
        }
    }

    buf
}

/// Build file info buffer from metadata.
///
/// Handles file info classes per MS-SMB2 2.4.1:
/// - FileBasicInformation (4)
/// - FileStandardInformation (5)
/// - FileAllInformation (18)
pub fn build_file_info(metadata: &rustsmb_vfs::Metadata, info_class: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    let is_dir = metadata.file_type == FileType::Directory;

    match info_class {
        // FileBasicInformation
        4 => {
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // CreationTime
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastAccessTime
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // LastWriteTime
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // ChangeTime
            let attrs = if is_dir { 0x10u32 } else { 0x80u32 };
            buf.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
            buf.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        }
        // FileStandardInformation
        5 => {
            buf.extend_from_slice(&metadata.size.to_le_bytes()); // AllocationSize
            buf.extend_from_slice(&metadata.size.to_le_bytes()); // EndOfFile
            buf.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
            buf.push(0); // DeletePending
            buf.push(if is_dir { 1 } else { 0 }); // Directory
            buf.extend_from_slice(&[0u8; 2]); // Reserved
        }
        // FileAllInformation (combination)
        18 => {
            // Basic info
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            buf.extend_from_slice(&current_filetime().to_le_bytes());
            let attrs = if is_dir { 0x10u32 } else { 0x80u32 };
            buf.extend_from_slice(&attrs.to_le_bytes());
            buf.extend_from_slice(&0u32.to_le_bytes());
            // Standard info
            buf.extend_from_slice(&metadata.size.to_le_bytes());
            buf.extend_from_slice(&metadata.size.to_le_bytes());
            buf.extend_from_slice(&1u32.to_le_bytes());
            buf.push(0);
            buf.push(if is_dir { 1 } else { 0 });
            buf.extend_from_slice(&[0u8; 2]);
            // Internal, EA, Access, Position info...
            buf.extend_from_slice(&[0u8; 48]);
        }
        _ => {
            // Unknown info class - return minimal data
            buf.extend_from_slice(&[0u8; 8]);
        }
    }

    buf
}

/// Build filesystem info buffer from FsStats.
///
/// Handles filesystem info classes per MS-SMB2 2.4.1 (file system information):
/// - FileFsVolumeInformation (1)
/// - FileFsSizeInformation (3)
/// - FileFsDeviceInformation (4)
/// - FileFsAttributeInformation (5)
/// - FileFsFullSizeInformation (7)
pub fn build_fs_info(fs_stats: &rustsmb_vfs::FsStats, info_class: u8) -> Vec<u8> {
    let mut buf = Vec::new();

    match info_class {
        // FileFsVolumeInformation (1)
        1 => {
            buf.extend_from_slice(&current_filetime().to_le_bytes()); // VolumeCreationTime
            buf.extend_from_slice(&fs_stats.fsid.to_le_bytes()[..4]); // VolumeSerialNumber (4 bytes)
            let volume_label = "RustSMB";
            let label_bytes: Vec<u16> = volume_label.encode_utf16().collect();
            let label_len = (label_bytes.len() * 2) as u32;
            buf.extend_from_slice(&label_len.to_le_bytes()); // VolumeLabelLength
            buf.push(0); // SupportsObjects = FALSE
            buf.push(0); // Reserved
            for c in label_bytes {
                buf.extend_from_slice(&c.to_le_bytes());
            }
        }
        // FileFsSizeInformation (3)
        3 => {
            let total_allocation_units = fs_stats.blocks;
            let available_units = fs_stats.blocks_available;
            let sectors_per_unit = 1u32;
            let bytes_per_sector = fs_stats.block_size;
            buf.extend_from_slice(&total_allocation_units.to_le_bytes()); // TotalAllocationUnits
            buf.extend_from_slice(&available_units.to_le_bytes()); // AvailableAllocationUnits
            buf.extend_from_slice(&sectors_per_unit.to_le_bytes()); // SectorsPerAllocationUnit
            buf.extend_from_slice(&bytes_per_sector.to_le_bytes()); // BytesPerSector
        }
        // FileFsDeviceInformation (4)
        4 => {
            buf.extend_from_slice(&0x00000007u32.to_le_bytes()); // DeviceType = FILE_DEVICE_DISK
            buf.extend_from_slice(&0x00000020u32.to_le_bytes()); // Characteristics = FILE_REMOTE_DEVICE
        }
        // FileFsAttributeInformation (5)
        5 => {
            // FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK
            let fs_attributes = 0x00000003u32;
            buf.extend_from_slice(&fs_attributes.to_le_bytes()); // FileSystemAttributes
            buf.extend_from_slice(&255u32.to_le_bytes()); // MaximumComponentNameLength
            let fs_name = "NTFS";
            let name_bytes: Vec<u16> = fs_name.encode_utf16().collect();
            let name_len = (name_bytes.len() * 2) as u32;
            buf.extend_from_slice(&name_len.to_le_bytes()); // FileSystemNameLength
            for c in name_bytes {
                buf.extend_from_slice(&c.to_le_bytes());
            }
        }
        // FileFsFullSizeInformation (7)
        7 => {
            let total_allocation_units = fs_stats.blocks;
            let caller_available_units = fs_stats.blocks_available;
            let actual_available_units = fs_stats.blocks_free;
            let sectors_per_unit = 1u32;
            let bytes_per_sector = fs_stats.block_size;
            buf.extend_from_slice(&total_allocation_units.to_le_bytes()); // TotalAllocationUnits
            buf.extend_from_slice(&caller_available_units.to_le_bytes()); // CallerAvailableAllocationUnits
            buf.extend_from_slice(&actual_available_units.to_le_bytes()); // ActualAvailableAllocationUnits
            buf.extend_from_slice(&sectors_per_unit.to_le_bytes()); // SectorsPerAllocationUnit
            buf.extend_from_slice(&bytes_per_sector.to_le_bytes()); // BytesPerSector
        }
        _ => {
            // Unknown info class - return minimal data
            buf.extend_from_slice(&[0u8; 8]);
        }
    }

    buf
}

/// Build security info buffer from requested security information flags.
///
/// Per MS-SMB2 2.4.6, this returns a SECURITY_DESCRIPTOR structure.
/// For simplicity, returns a minimal self-relative security descriptor.
pub fn build_security_info(additional_info: u32) -> Vec<u8> {
    // Minimal self-relative security descriptor
    // Structure: SECURITY_DESCRIPTOR (self-relative form)
    let mut buf = Vec::new();

    // Header
    buf.push(1); // Revision = 1
    buf.push(0); // Sbz1 = 0
    let control = 0x8004u16; // SE_SELF_RELATIVE | SE_DACL_PRESENT
    buf.extend_from_slice(&control.to_le_bytes()); // Control

    // Offsets (all 0 means not present, except DACL if requested)
    let owner_offset = 0u32;
    let group_offset = 0u32;
    let sacl_offset = 0u32;

    // If DACL is requested, we'll include a minimal empty DACL
    // Additional info flags: OWNER=0x01, GROUP=0x02, DACL=0x04, SACL=0x08
    let dacl_requested = (additional_info & 0x04) != 0;

    if dacl_requested {
        // SECURITY_DESCRIPTOR header (20 bytes) + DACL follows
        let dacl_offset = 20u32;
        buf.extend_from_slice(&owner_offset.to_le_bytes()); // OffsetOwner
        buf.extend_from_slice(&group_offset.to_le_bytes()); // OffsetGroup
        buf.extend_from_slice(&sacl_offset.to_le_bytes()); // OffsetSacl
        buf.extend_from_slice(&dacl_offset.to_le_bytes()); // OffsetDacl

        // Minimal DACL (allows all access) - ACL structure
        buf.push(2); // AclRevision = 2
        buf.push(0); // Sbz1
        let acl_size = 8u16; // Just the header, no ACEs
        buf.extend_from_slice(&acl_size.to_le_bytes()); // AclSize
        let ace_count = 0u16;
        buf.extend_from_slice(&ace_count.to_le_bytes()); // AceCount
        let sbz2 = 0u16;
        buf.extend_from_slice(&sbz2.to_le_bytes()); // Sbz2
    } else {
        // No DACL - all offsets are 0
        buf.extend_from_slice(&owner_offset.to_le_bytes());
        buf.extend_from_slice(&group_offset.to_le_bytes());
        buf.extend_from_slice(&sacl_offset.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // OffsetDacl = 0
    }

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // build_fs_info Unit Tests - MS-SMB2 2.4.1 Filesystem Info Classes
    // =========================================================================

    #[test]
    fn test_build_fs_info_volume_information() {
        // FileFsVolumeInformation (info class 1)
        let fs_stats = rustsmb_vfs::FsStats {
            blocks: 1000000,
            blocks_free: 500000,
            blocks_available: 450000,
            block_size: 4096,
            files: 100000,
            files_free: 50000,
            fsid: 0x12345678ABCDEF00,
            namelen: 255,
        };

        let buf = build_fs_info(&fs_stats, 1);

        // Should have: VolumeCreationTime(8) + SerialNumber(4) + LabelLength(4) +
        // SupportsObjects(1) + Reserved(1) + Label(14 bytes for "RustSMB")
        assert!(buf.len() >= 18, "Volume info should have at least header");

        // Check VolumeSerialNumber comes from fsid (bytes 8-11)
        let serial = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(
            serial, 0xABCDEF00u32,
            "Serial number from lower 32 bits of fsid"
        );
    }

    #[test]
    fn test_build_fs_info_size_information() {
        // FileFsSizeInformation (info class 3)
        let fs_stats = rustsmb_vfs::FsStats {
            blocks: 1000000,
            blocks_free: 500000,
            blocks_available: 450000,
            block_size: 4096,
            files: 100000,
            files_free: 50000,
            fsid: 0,
            namelen: 255,
        };

        let buf = build_fs_info(&fs_stats, 3);

        // Should have: TotalAllocationUnits(8) + AvailableAllocationUnits(8) +
        // SectorsPerAllocationUnit(4) + BytesPerSector(4) = 24 bytes
        assert_eq!(buf.len(), 24, "Size info should be 24 bytes");

        // Check TotalAllocationUnits
        let total = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(total, 1000000, "Total allocation units");

        // Check AvailableAllocationUnits
        let available = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(available, 450000, "Available allocation units");

        // Check BytesPerSector
        let bytes_per_sector = u32::from_le_bytes(buf[20..24].try_into().unwrap());
        assert_eq!(bytes_per_sector, 4096, "Bytes per sector");
    }

    #[test]
    fn test_build_fs_info_device_information() {
        // FileFsDeviceInformation (info class 4)
        let fs_stats = rustsmb_vfs::FsStats::default();

        let buf = build_fs_info(&fs_stats, 4);

        // Should have: DeviceType(4) + Characteristics(4) = 8 bytes
        assert_eq!(buf.len(), 8, "Device info should be 8 bytes");

        // Check DeviceType = FILE_DEVICE_DISK (0x07)
        let device_type = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(
            device_type, 0x00000007,
            "Device type should be FILE_DEVICE_DISK"
        );

        // Check Characteristics includes FILE_REMOTE_DEVICE (0x20)
        let characteristics = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(
            characteristics & 0x20,
            0x20,
            "Characteristics should include FILE_REMOTE_DEVICE"
        );
    }

    #[test]
    fn test_build_fs_info_attribute_information() {
        // FileFsAttributeInformation (info class 5)
        let fs_stats = rustsmb_vfs::FsStats::default();

        let buf = build_fs_info(&fs_stats, 5);

        // Should have: FileSystemAttributes(4) + MaxComponentNameLength(4) +
        // FileSystemNameLength(4) + Name (variable)
        assert!(
            buf.len() >= 12,
            "Attribute info should have at least header"
        );

        // Check FileSystemAttributes
        let attrs = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        // Should have FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES = 0x03
        assert_eq!(attrs & 0x03, 0x03, "Should have case-related attributes");

        // Check MaxComponentNameLength = 255
        let max_name_len = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        assert_eq!(max_name_len, 255, "Max component name length");
    }

    #[test]
    fn test_build_fs_info_full_size_information() {
        // FileFsFullSizeInformation (info class 7)
        let fs_stats = rustsmb_vfs::FsStats {
            blocks: 1000000,
            blocks_free: 500000,
            blocks_available: 450000,
            block_size: 4096,
            files: 100000,
            files_free: 50000,
            fsid: 0,
            namelen: 255,
        };

        let buf = build_fs_info(&fs_stats, 7);

        // Should have: TotalAllocationUnits(8) + CallerAvailableAllocationUnits(8) +
        // ActualAvailableAllocationUnits(8) + SectorsPerAllocationUnit(4) +
        // BytesPerSector(4) = 32 bytes
        assert_eq!(buf.len(), 32, "Full size info should be 32 bytes");

        // Check TotalAllocationUnits
        let total = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(total, 1000000, "Total allocation units");

        // Check CallerAvailableAllocationUnits (blocks_available)
        let caller_available = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(caller_available, 450000, "Caller available");

        // Check ActualAvailableAllocationUnits (blocks_free)
        let actual_available = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        assert_eq!(actual_available, 500000, "Actual available");
    }

    #[test]
    fn test_build_fs_info_unknown_class() {
        // Unknown info class should return minimal data
        let fs_stats = rustsmb_vfs::FsStats::default();

        let buf = build_fs_info(&fs_stats, 99);

        assert_eq!(buf.len(), 8, "Unknown class should return 8 bytes of zeros");
        assert!(buf.iter().all(|&b| b == 0), "Should be all zeros");
    }

    // =========================================================================
    // build_security_info Unit Tests - MS-SMB2 2.4.6 Security Descriptor
    // =========================================================================

    #[test]
    fn test_build_security_info_no_dacl() {
        // Request without DACL flag (0x00)
        let buf = build_security_info(0x00);

        // Should have minimal security descriptor header (20 bytes)
        assert_eq!(
            buf.len(),
            20,
            "Security descriptor without DACL should be 20 bytes"
        );

        // Check Revision = 1
        assert_eq!(buf[0], 1, "Revision should be 1");

        // Check Control field (bytes 2-3)
        let control = u16::from_le_bytes([buf[2], buf[3]]);
        assert_eq!(
            control & 0x8000,
            0x8000,
            "SE_SELF_RELATIVE flag should be set"
        );
    }

    #[test]
    fn test_build_security_info_with_dacl() {
        // Request with DACL flag (0x04)
        let buf = build_security_info(0x04);

        // Should have security descriptor header (20 bytes) + DACL header (8 bytes) = 28 bytes
        assert_eq!(
            buf.len(),
            28,
            "Security descriptor with DACL should be 28 bytes"
        );

        // Check Revision = 1
        assert_eq!(buf[0], 1, "Revision should be 1");

        // Check Control field (bytes 2-3) has SE_SELF_RELATIVE and SE_DACL_PRESENT
        let control = u16::from_le_bytes([buf[2], buf[3]]);
        assert_eq!(
            control & 0x8004,
            0x8004,
            "SE_SELF_RELATIVE and SE_DACL_PRESENT should be set"
        );

        // Check OffsetDacl (bytes 16-19) points to 20
        let dacl_offset = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        assert_eq!(dacl_offset, 20, "DACL offset should be 20");

        // Check DACL AclRevision = 2 (at offset 20)
        assert_eq!(buf[20], 2, "DACL AclRevision should be 2");

        // Check ACE count = 0 (at offset 24-25)
        let ace_count = u16::from_le_bytes([buf[24], buf[25]]);
        assert_eq!(ace_count, 0, "ACE count should be 0 (empty DACL)");
    }

    #[test]
    fn test_build_security_info_dacl_structure() {
        // Verify DACL structure in detail
        let buf = build_security_info(0x04);

        // DACL starts at offset 20
        // ACL structure: Revision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2)
        let acl_revision = buf[20];
        let acl_sbz1 = buf[21];
        let acl_size = u16::from_le_bytes([buf[22], buf[23]]);
        let ace_count = u16::from_le_bytes([buf[24], buf[25]]);
        let acl_sbz2 = u16::from_le_bytes([buf[26], buf[27]]);

        assert_eq!(acl_revision, 2, "ACL Revision");
        assert_eq!(acl_sbz1, 0, "ACL Sbz1");
        assert_eq!(acl_size, 8, "ACL Size (header only)");
        assert_eq!(ace_count, 0, "ACE Count");
        assert_eq!(acl_sbz2, 0, "ACL Sbz2");
    }

    // =========================================================================
    // build_file_info Unit Tests
    // =========================================================================

    #[test]
    fn test_build_file_info_basic() {
        let metadata = rustsmb_vfs::Metadata {
            file_type: FileType::Regular,
            size: 1024,
            ..Default::default()
        };

        let buf = build_file_info(&metadata, 4); // FileBasicInformation

        // Should have: 4 timestamps (8 bytes each) + FileAttributes (4) + Reserved (4) = 40 bytes
        assert_eq!(buf.len(), 40, "FileBasicInformation should be 40 bytes");

        // Check attributes at offset 32 (after 4 timestamps)
        let attrs = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        assert_eq!(attrs, 0x80, "File should have NORMAL attribute");
    }

    #[test]
    fn test_build_file_info_directory() {
        let metadata = rustsmb_vfs::Metadata {
            file_type: FileType::Directory,
            size: 0,
            ..Default::default()
        };

        let buf = build_file_info(&metadata, 4); // FileBasicInformation

        // Check attributes - directory should have 0x10
        let attrs = u32::from_le_bytes(buf[32..36].try_into().unwrap());
        assert_eq!(attrs, 0x10, "Directory should have DIRECTORY attribute");
    }

    #[test]
    fn test_build_file_info_standard() {
        let metadata = rustsmb_vfs::Metadata {
            file_type: FileType::Regular,
            size: 4096,
            ..Default::default()
        };

        let buf = build_file_info(&metadata, 5); // FileStandardInformation

        // Should have: AllocationSize(8) + EndOfFile(8) + NumberOfLinks(4) +
        // DeletePending(1) + Directory(1) + Reserved(2) = 24 bytes
        assert_eq!(buf.len(), 24, "FileStandardInformation should be 24 bytes");

        // Check size at offset 0
        let alloc_size = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        assert_eq!(alloc_size, 4096, "AllocationSize");

        let end_of_file = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        assert_eq!(end_of_file, 4096, "EndOfFile");
    }
}
