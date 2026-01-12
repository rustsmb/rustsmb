//! Property-based tests for SMB2 protocol parsing.
//!
//! These tests verify that all message types can roundtrip through
//! serialization/deserialization without data loss.

#[cfg(test)]
mod tests {
    use crate::commands::*;
    use crate::header::{Smb2Command, Smb2Flags, Smb2Header};
    use crate::transform::Smb2TransformHeader;
    use binrw::{BinRead, BinWrite};
    use proptest::prelude::*;
    use std::io::Cursor;

    // Strategy generators for common types

    fn arb_smb2_command() -> impl Strategy<Value = Smb2Command> {
        prop_oneof![
            Just(Smb2Command::Negotiate),
            Just(Smb2Command::SessionSetup),
            Just(Smb2Command::Logoff),
            Just(Smb2Command::TreeConnect),
            Just(Smb2Command::TreeDisconnect),
            Just(Smb2Command::Create),
            Just(Smb2Command::Close),
            Just(Smb2Command::Flush),
            Just(Smb2Command::Read),
            Just(Smb2Command::Write),
            Just(Smb2Command::Lock),
            Just(Smb2Command::Ioctl),
            Just(Smb2Command::Cancel),
            Just(Smb2Command::Echo),
            Just(Smb2Command::QueryDirectory),
            Just(Smb2Command::ChangeNotify),
            Just(Smb2Command::QueryInfo),
            Just(Smb2Command::SetInfo),
            Just(Smb2Command::OplockBreak),
        ]
    }

    fn arb_oplock_level() -> impl Strategy<Value = OplockLevel> {
        prop_oneof![
            Just(OplockLevel::None),
            Just(OplockLevel::LevelII),
            Just(OplockLevel::Exclusive),
            Just(OplockLevel::Batch),
            Just(OplockLevel::Lease),
        ]
    }

    fn arb_create_oplock_level() -> impl Strategy<Value = CreateOplockLevel> {
        prop_oneof![
            Just(CreateOplockLevel::None),
            Just(CreateOplockLevel::LevelII),
            Just(CreateOplockLevel::Exclusive),
            Just(CreateOplockLevel::Batch),
            Just(CreateOplockLevel::Lease),
        ]
    }

    fn arb_file_information_class() -> impl Strategy<Value = FileInformationClass> {
        prop_oneof![
            Just(FileInformationClass::FileDirectoryInformation),
            Just(FileInformationClass::FileFullDirectoryInformation),
            Just(FileInformationClass::FileIdFullDirectoryInformation),
            Just(FileInformationClass::FileBothDirectoryInformation),
            Just(FileInformationClass::FileIdBothDirectoryInformation),
            Just(FileInformationClass::FileNamesInformation),
        ]
    }

    fn arb_impersonation_level() -> impl Strategy<Value = u32> {
        prop_oneof![
            Just(0u32), // Anonymous
            Just(1u32), // Identification
            Just(2u32), // Impersonation
            Just(3u32), // Delegation
        ]
    }

    fn arb_share_type() -> impl Strategy<Value = ShareType> {
        prop_oneof![
            Just(ShareType::Disk),
            Just(ShareType::Pipe),
            Just(ShareType::Print),
        ]
    }

    fn arb_info_type() -> impl Strategy<Value = InfoType> {
        prop_oneof![
            Just(InfoType::File),
            Just(InfoType::FileSystem),
            Just(InfoType::Security),
            Just(InfoType::Quota),
        ]
    }

    fn arb_set_info_type() -> impl Strategy<Value = SetInfoType> {
        prop_oneof![
            Just(SetInfoType::File),
            Just(SetInfoType::FileSystem),
            Just(SetInfoType::Security),
            Just(SetInfoType::Quota),
        ]
    }

    fn arb_16_bytes() -> impl Strategy<Value = [u8; 16]> {
        prop::array::uniform16(any::<u8>())
    }

    // SMB2 Header roundtrip tests

    proptest! {
        #[test]
        fn test_header_roundtrip(
            credit_charge: u16,
            status: u32,
            command in arb_smb2_command(),
            credits: u16,
            flags: u32,
            next_command: u32,
            message_id: u64,
            async_id: u32,
            tree_id: u32,
            session_id: u64,
            signature in arb_16_bytes(),
        ) {
            let header = Smb2Header {
                structure_size: 64,
                credit_charge,
                status,
                command,
                credits,
                flags: Smb2Flags(flags),
                next_command,
                message_id,
                async_id,
                tree_id,
                session_id,
                signature,
            };

            let mut buf = Vec::new();
            header.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = Smb2Header::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.structure_size, 64);
            prop_assert_eq!(parsed.credit_charge, credit_charge);
            prop_assert_eq!(parsed.status, status);
            prop_assert_eq!(parsed.command, command);
            prop_assert_eq!(parsed.credits, credits);
            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.next_command, next_command);
            prop_assert_eq!(parsed.message_id, message_id);
            prop_assert_eq!(parsed.async_id, async_id);
            prop_assert_eq!(parsed.tree_id, tree_id);
            prop_assert_eq!(parsed.session_id, session_id);
            prop_assert_eq!(parsed.signature, signature);
        }

        #[test]
        fn test_transform_header_roundtrip(
            signature in arb_16_bytes(),
            nonce in arb_16_bytes(),
            original_message_size: u32,
            flags: u16,
            session_id: u64,
        ) {
            let header = Smb2TransformHeader {
                signature,
                nonce,
                original_message_size,
                reserved: 0,
                flags,
                session_id,
            };

            let mut buf = Vec::new();
            header.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = Smb2TransformHeader::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.signature, signature);
            prop_assert_eq!(parsed.nonce, nonce);
            prop_assert_eq!(parsed.original_message_size, original_message_size);
            prop_assert_eq!(parsed.flags, flags);
            prop_assert_eq!(parsed.session_id, session_id);
        }

        // NEGOTIATE command tests

        #[test]
        fn test_negotiate_request_roundtrip(
            security_mode: u16,
            capabilities: u32,
            client_guid in arb_16_bytes(),
        ) {
            let req = NegotiateRequest {
                structure_size: 36,
                dialect_count: 0,
                security_mode: SecurityMode(security_mode),
                reserved: 0,
                capabilities: Capabilities(capabilities),
                client_guid,
                negotiate_context_offset: 0,
                negotiate_context_count: 0,
                reserved2: 0,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = NegotiateRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.structure_size, 36);
            prop_assert_eq!(parsed.security_mode.0, security_mode);
            prop_assert_eq!(parsed.capabilities.0, capabilities);
            prop_assert_eq!(parsed.client_guid, client_guid);
        }

        #[test]
        fn test_negotiate_response_roundtrip(
            security_mode: u16,
            dialect_revision: u16,
            server_guid in arb_16_bytes(),
            capabilities: u32,
            max_transact_size: u32,
            max_read_size: u32,
            max_write_size: u32,
            system_time: u64,
            server_start_time: u64,
        ) {
            let resp = NegotiateResponse {
                structure_size: 65,
                security_mode: SecurityMode(security_mode),
                dialect_revision,
                negotiate_context_count: 0,
                server_guid,
                capabilities: Capabilities(capabilities),
                max_transact_size,
                max_read_size,
                max_write_size,
                system_time,
                server_start_time,
                security_buffer_offset: 0,
                security_buffer_length: 0,
                negotiate_context_offset: 0,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = NegotiateResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.dialect_revision, dialect_revision);
            prop_assert_eq!(parsed.server_guid, server_guid);
            prop_assert_eq!(parsed.max_transact_size, max_transact_size);
            prop_assert_eq!(parsed.max_read_size, max_read_size);
            prop_assert_eq!(parsed.max_write_size, max_write_size);
        }

        // CREATE command tests

        #[test]
        fn test_create_request_roundtrip(
            oplock_level in arb_create_oplock_level(),
            impersonation in arb_impersonation_level(),
            desired_access: u32,
            file_attributes: u32,
            share_access: u32,
            create_disposition in 0u32..6,
            create_options: u32,
        ) {
            let req = CreateRequest {
                structure_size: 57,
                security_flags: 0,
                requested_oplock_level: oplock_level,
                impersonation_level: impersonation,
                smb_create_flags: 0,
                reserved: 0,
                desired_access,
                file_attributes,
                share_access,
                create_disposition,
                create_options,
                name_offset: 0,
                name_length: 0,
                create_contexts_offset: 0,
                create_contexts_length: 0,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = CreateRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.requested_oplock_level, oplock_level);
            prop_assert_eq!(parsed.impersonation_level, impersonation);
            prop_assert_eq!(parsed.desired_access, desired_access);
            prop_assert_eq!(parsed.file_attributes, file_attributes);
            prop_assert_eq!(parsed.share_access, share_access);
            prop_assert_eq!(parsed.create_disposition, create_disposition);
            prop_assert_eq!(parsed.create_options, create_options);
        }

        #[test]
        fn test_create_response_roundtrip(
            oplock_level in arb_create_oplock_level(),
            create_action in 0u32..4,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            change_time: u64,
            allocation_size: u64,
            end_of_file: u64,
            file_attributes: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let resp = CreateResponse {
                structure_size: 89,
                oplock_level,
                flags: CreateResponseFlags(0),
                create_action,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                allocation_size,
                end_of_file,
                file_attributes,
                reserved2: 0,
                file_id_persistent,
                file_id_volatile,
                create_contexts_offset: 0,
                create_contexts_length: 0,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = CreateResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.oplock_level, oplock_level);
            prop_assert_eq!(parsed.create_action, create_action);
            prop_assert_eq!(parsed.creation_time, creation_time);
            prop_assert_eq!(parsed.allocation_size, allocation_size);
            prop_assert_eq!(parsed.end_of_file, end_of_file);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        // READ command tests

        #[test]
        fn test_read_request_roundtrip(
            flags: u8,
            length: u32,
            offset: u64,
            file_id_persistent: u64,
            file_id_volatile: u64,
            minimum_count: u32,
            channel: u32,
            remaining_bytes: u32,
        ) {
            let req = ReadRequest {
                structure_size: 49,
                padding: 0x50,
                flags: ReadFlags(flags),
                length,
                offset,
                file_id_persistent,
                file_id_volatile,
                minimum_count,
                channel,
                remaining_bytes,
                read_channel_info_offset: 0,
                read_channel_info_length: 0,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = ReadRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.length, length);
            prop_assert_eq!(parsed.offset, offset);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
            prop_assert_eq!(parsed.remaining_bytes, remaining_bytes);
        }

        #[test]
        fn test_read_response_roundtrip(
            data_offset: u8,
            data_length: u32,
            data_remaining: u32,
            flags: u32,
        ) {
            let resp = ReadResponse {
                structure_size: 17,
                data_offset,
                reserved: 0,
                data_length,
                data_remaining,
                flags: ReadResponseFlags(flags),
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = ReadResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.data_offset, data_offset);
            prop_assert_eq!(parsed.data_length, data_length);
            prop_assert_eq!(parsed.data_remaining, data_remaining);
            prop_assert_eq!(parsed.flags.0, flags);
        }

        // WRITE command tests

        #[test]
        fn test_write_request_roundtrip(
            data_offset: u16,
            length: u32,
            offset: u64,
            file_id_persistent: u64,
            file_id_volatile: u64,
            channel: u32,
            remaining_bytes: u32,
            flags: u32,
        ) {
            let req = WriteRequest {
                structure_size: 49,
                data_offset,
                length,
                offset,
                file_id_persistent,
                file_id_volatile,
                channel,
                remaining_bytes,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
                flags: WriteFlags(flags),
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = WriteRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.data_offset, data_offset);
            prop_assert_eq!(parsed.length, length);
            prop_assert_eq!(parsed.offset, offset);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
            prop_assert_eq!(parsed.flags.0, flags);
        }

        #[test]
        fn test_write_response_roundtrip(
            count: u32,
            remaining: u32,
        ) {
            let resp = WriteResponse {
                structure_size: 17,
                reserved: 0,
                count,
                remaining,
                write_channel_info_offset: 0,
                write_channel_info_length: 0,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = WriteResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.count, count);
            prop_assert_eq!(parsed.remaining, remaining);
        }

        // CLOSE command tests

        #[test]
        fn test_close_request_roundtrip(
            flags: u16,
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let req = CloseRequest {
                structure_size: 24,
                flags: CloseFlags(flags),
                reserved: 0,
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = CloseRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        #[test]
        fn test_close_response_roundtrip(
            flags: u16,
            creation_time: u64,
            last_access_time: u64,
            last_write_time: u64,
            change_time: u64,
            allocation_size: u64,
            end_of_file: u64,
            file_attributes: u32,
        ) {
            let resp = CloseResponse {
                structure_size: 60,
                flags: CloseFlags(flags),
                reserved: 0,
                creation_time,
                last_access_time,
                last_write_time,
                change_time,
                allocation_size,
                end_of_file,
                file_attributes,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = CloseResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.creation_time, creation_time);
            prop_assert_eq!(parsed.allocation_size, allocation_size);
            prop_assert_eq!(parsed.end_of_file, end_of_file);
            prop_assert_eq!(parsed.file_attributes, file_attributes);
        }

        // LOCK command tests

        #[test]
        fn test_lock_request_roundtrip(
            lock_count in 1u16..10u16,
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let req = LockRequest {
                structure_size: 48,
                lock_count,
                lock_sequence: 0,
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = LockRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.lock_count, lock_count);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        #[test]
        fn test_lock_element_roundtrip(
            offset: u64,
            length: u64,
            flags: u32,
        ) {
            let elem = LockElement {
                offset,
                length,
                flags: LockFlags(flags),
                reserved: 0,
            };

            let mut buf = Vec::new();
            elem.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = LockElement::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.offset, offset);
            prop_assert_eq!(parsed.length, length);
            prop_assert_eq!(parsed.flags.0, flags);
        }

        // QUERY_DIRECTORY command tests

        #[test]
        fn test_query_directory_request_roundtrip(
            file_information_class in arb_file_information_class(),
            flags: u8,
            file_index: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
            output_buffer_length: u32,
        ) {
            let req = QueryDirectoryRequest {
                structure_size: 33,
                file_information_class,
                flags: QueryDirectoryFlags(flags),
                file_index,
                file_id_persistent,
                file_id_volatile,
                file_name_offset: 0,
                file_name_length: 0,
                output_buffer_length,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = QueryDirectoryRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.file_information_class, file_information_class);
            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.file_index, file_index);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
            prop_assert_eq!(parsed.output_buffer_length, output_buffer_length);
        }

        #[test]
        fn test_query_directory_response_roundtrip(
            output_buffer_offset: u16,
            output_buffer_length: u32,
        ) {
            let resp = QueryDirectoryResponse {
                structure_size: 9,
                output_buffer_offset,
                output_buffer_length,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = QueryDirectoryResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.output_buffer_offset, output_buffer_offset);
            prop_assert_eq!(parsed.output_buffer_length, output_buffer_length);
        }

        // QUERY_INFO command tests

        #[test]
        fn test_query_info_request_roundtrip(
            info_type in arb_info_type(),
            file_info_class: u8,
            output_buffer_length: u32,
            additional_information: u32,
            flags: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let req = QueryInfoRequest {
                structure_size: 41,
                info_type,
                file_info_class,
                output_buffer_length,
                input_buffer_offset: 0,
                reserved: 0,
                input_buffer_length: 0,
                additional_information: AdditionalInformation(additional_information),
                flags: QueryInfoFlags(flags),
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = QueryInfoRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.info_type, info_type);
            prop_assert_eq!(parsed.file_info_class, file_info_class);
            prop_assert_eq!(parsed.output_buffer_length, output_buffer_length);
            prop_assert_eq!(parsed.additional_information.0, additional_information);
            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        #[test]
        fn test_query_info_response_roundtrip(
            output_buffer_offset: u16,
            output_buffer_length: u32,
        ) {
            let resp = QueryInfoResponse {
                structure_size: 9,
                output_buffer_offset,
                output_buffer_length,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = QueryInfoResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.output_buffer_offset, output_buffer_offset);
            prop_assert_eq!(parsed.output_buffer_length, output_buffer_length);
        }

        // SET_INFO command tests

        #[test]
        fn test_set_info_request_roundtrip(
            info_type in arb_set_info_type(),
            file_info_class: u8,
            buffer_length: u32,
            additional_information: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let req = SetInfoRequest {
                structure_size: 33,
                info_type,
                file_info_class,
                buffer_length,
                buffer_offset: 0,
                reserved: 0,
                additional_information,
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = SetInfoRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.info_type, info_type);
            prop_assert_eq!(parsed.file_info_class, file_info_class);
            prop_assert_eq!(parsed.buffer_length, buffer_length);
            prop_assert_eq!(parsed.additional_information, additional_information);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        // FLUSH command tests

        #[test]
        fn test_flush_request_roundtrip(
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let req = FlushRequest {
                structure_size: 24,
                reserved1: 0,
                reserved2: 0,
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = FlushRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        // SESSION_SETUP command tests

        #[test]
        fn test_session_setup_request_roundtrip(
            flags: u8,
            security_mode: u8,
            capabilities: u32,
            channel: u32,
            previous_session_id: u64,
        ) {
            let req = SessionSetupRequest {
                structure_size: 25,
                flags: SessionSetupFlags(flags),
                security_mode: SessionSecurityMode(security_mode),
                capabilities: SessionCapabilities(capabilities),
                channel,
                security_buffer_offset: 0,
                security_buffer_length: 0,
                previous_session_id,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = SessionSetupRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.security_mode.0, security_mode);
            prop_assert_eq!(parsed.capabilities.0, capabilities);
            prop_assert_eq!(parsed.channel, channel);
            prop_assert_eq!(parsed.previous_session_id, previous_session_id);
        }

        #[test]
        fn test_session_setup_response_roundtrip(
            session_flags: u16,
        ) {
            let resp = SessionSetupResponse {
                structure_size: 9,
                session_flags: SessionFlags(session_flags),
                security_buffer_offset: 0,
                security_buffer_length: 0,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = SessionSetupResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.session_flags.0, session_flags);
        }

        // TREE_CONNECT command tests

        #[test]
        fn test_tree_connect_request_roundtrip(
            flags: u16,
        ) {
            let req = TreeConnectRequest {
                structure_size: 9,
                flags: TreeConnectFlags(flags),
                path_offset: 0,
                path_length: 0,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = TreeConnectRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.flags.0, flags);
        }

        #[test]
        fn test_tree_connect_response_roundtrip(
            share_type in arb_share_type(),
            share_flags: u32,
            capabilities: u32,
            maximal_access: u32,
        ) {
            let resp = TreeConnectResponse {
                structure_size: 16,
                share_type,
                reserved: 0,
                share_flags: ShareFlags(share_flags),
                capabilities: ShareCapabilities(capabilities),
                maximal_access,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = TreeConnectResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.share_type, share_type);
            prop_assert_eq!(parsed.share_flags.0, share_flags);
            prop_assert_eq!(parsed.capabilities.0, capabilities);
            prop_assert_eq!(parsed.maximal_access, maximal_access);
        }

        // IOCTL command tests

        #[test]
        fn test_ioctl_request_roundtrip(
            ctl_code: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
            max_input_response: u32,
            max_output_response: u32,
            flags: u32,
        ) {
            let req = IoctlRequest {
                structure_size: 57,
                reserved: 0,
                ctl_code,
                file_id_persistent,
                file_id_volatile,
                input_offset: 0,
                input_count: 0,
                max_input_response,
                output_offset: 0,
                output_count: 0,
                max_output_response,
                flags: IoctlFlags(flags),
                reserved2: 0,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = IoctlRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.ctl_code, ctl_code);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
            prop_assert_eq!(parsed.max_input_response, max_input_response);
            prop_assert_eq!(parsed.max_output_response, max_output_response);
            prop_assert_eq!(parsed.flags.0, flags);
        }

        #[test]
        fn test_ioctl_response_roundtrip(
            ctl_code: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let resp = IoctlResponse {
                structure_size: 49,
                reserved: 0,
                ctl_code,
                file_id_persistent,
                file_id_volatile,
                input_offset: 0,
                input_count: 0,
                output_offset: 0,
                output_count: 0,
                flags: 0,
                reserved2: 0,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = IoctlResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.ctl_code, ctl_code);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        // CHANGE_NOTIFY command tests

        #[test]
        fn test_change_notify_request_roundtrip(
            flags: u16,
            output_buffer_length: u32,
            file_id_persistent: u64,
            file_id_volatile: u64,
            completion_filter: u32,
        ) {
            let req = ChangeNotifyRequest {
                structure_size: 32,
                flags: ChangeNotifyFlags(flags),
                output_buffer_length,
                file_id_persistent,
                file_id_volatile,
                completion_filter: CompletionFilter(completion_filter),
                reserved: 0,
            };

            let mut buf = Vec::new();
            req.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = ChangeNotifyRequest::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.flags.0, flags);
            prop_assert_eq!(parsed.output_buffer_length, output_buffer_length);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
            prop_assert_eq!(parsed.completion_filter.0, completion_filter);
        }

        #[test]
        fn test_change_notify_response_roundtrip(
            output_buffer_offset: u16,
            output_buffer_length: u32,
        ) {
            let resp = ChangeNotifyResponse {
                structure_size: 9,
                output_buffer_offset,
                output_buffer_length,
            };

            let mut buf = Vec::new();
            resp.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = ChangeNotifyResponse::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.output_buffer_offset, output_buffer_offset);
            prop_assert_eq!(parsed.output_buffer_length, output_buffer_length);
        }

        // OPLOCK_BREAK command tests

        #[test]
        fn test_oplock_break_notification_roundtrip(
            oplock_level in arb_oplock_level(),
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let notif = OplockBreakNotification {
                structure_size: 24,
                oplock_level,
                reserved: 0,
                reserved2: 0,
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            notif.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = OplockBreakNotification::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.oplock_level, oplock_level);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }

        #[test]
        fn test_oplock_break_acknowledgment_roundtrip(
            oplock_level in arb_oplock_level(),
            file_id_persistent: u64,
            file_id_volatile: u64,
        ) {
            let ack = OplockBreakAcknowledgment {
                structure_size: 24,
                oplock_level,
                reserved: 0,
                reserved2: 0,
                file_id_persistent,
                file_id_volatile,
            };

            let mut buf = Vec::new();
            ack.write(&mut Cursor::new(&mut buf)).unwrap();

            let parsed = OplockBreakAcknowledgment::read(&mut Cursor::new(&buf)).unwrap();

            prop_assert_eq!(parsed.oplock_level, oplock_level);
            prop_assert_eq!(parsed.file_id_persistent, file_id_persistent);
            prop_assert_eq!(parsed.file_id_volatile, file_id_volatile);
        }
    }

    // Edge case tests for boundary values (non-proptest)

    #[test]
    fn test_header_max_values() {
        let header = Smb2Header {
            structure_size: 64,
            credit_charge: u16::MAX,
            status: u32::MAX,
            command: Smb2Command::OplockBreak,
            credits: u16::MAX,
            flags: Smb2Flags(u32::MAX),
            next_command: u32::MAX,
            message_id: u64::MAX,
            async_id: u32::MAX,
            tree_id: u32::MAX,
            session_id: u64::MAX,
            signature: [0xFF; 16],
        };

        let mut buf = Vec::new();
        header.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = Smb2Header::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.credit_charge, u16::MAX);
        assert_eq!(parsed.message_id, u64::MAX);
        assert_eq!(parsed.session_id, u64::MAX);
    }

    #[test]
    fn test_header_min_values() {
        let header = Smb2Header {
            structure_size: 64,
            credit_charge: 0,
            status: 0,
            command: Smb2Command::Negotiate,
            credits: 0,
            flags: Smb2Flags(0),
            next_command: 0,
            message_id: 0,
            async_id: 0,
            tree_id: 0,
            session_id: 0,
            signature: [0; 16],
        };

        let mut buf = Vec::new();
        header.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = Smb2Header::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.credit_charge, 0);
        assert_eq!(parsed.message_id, 0);
    }

    // Simple roundtrip tests for commands without variable fields

    #[test]
    fn test_echo_roundtrip() {
        let req = EchoRequest {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = EchoRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);

        let resp = EchoResponse {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = EchoResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);
    }

    #[test]
    fn test_logoff_roundtrip() {
        let req = LogoffRequest {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = LogoffRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);

        let resp = LogoffResponse {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = LogoffResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);
    }

    #[test]
    fn test_tree_disconnect_roundtrip() {
        let req = TreeDisconnectRequest {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = TreeDisconnectRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);

        let resp = TreeDisconnectResponse {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        resp.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = TreeDisconnectResponse::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);
    }

    #[test]
    fn test_cancel_roundtrip() {
        let req = CancelRequest {
            structure_size: 4,
            reserved: 0,
        };

        let mut buf = Vec::new();
        req.write(&mut Cursor::new(&mut buf)).unwrap();

        let parsed = CancelRequest::read(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(parsed.structure_size, 4);
    }
}
