//TODO: send messages - receive message
//	metadata: session status, remote peer key, time start

pub struct PubkyDataBackupFormatter {
    file_format: u8,
    pubky_data_version: u8,
    serial_id: u8,
    reserved_field: u8,
    //TODO: signature
}

impl PubkyDataBackupFormatter {
    pub fn new() -> Self {
        PubkyDataBackupFormatter {
            file_format: 0,
            pubky_data_version: 0,
            serial_id: 0,
            reserved_field: 0,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(4);
        buffer.push(self.file_format);
        buffer.push(self.pubky_data_version);
        buffer.push(self.serial_id);
        buffer.push(self.reserved_field);
        return buffer;
    }

    pub fn deserialize(mut raw_bytes: Vec<u8>) -> Result<Self, ()> {
        if raw_bytes.len() < 4 {
            return Err(());
        }
        let file_format = raw_bytes.remove(0);
        let pubky_data_version = raw_bytes.remove(0);
        let serial_id = raw_bytes.remove(0);
        let reserved_field = raw_bytes.remove(0);
        Ok(PubkyDataBackupFormatter {
            file_format,
            pubky_data_version,
            serial_id,
            reserved_field,
        })
    }
}
