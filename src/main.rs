use std::net::TcpStream;
use std::env;
use std::process;
use std::io::{Read, Write};
use std::convert::TryInto;
use std::fmt;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    UnsupportedProtocol,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(io) => io.fmt(f),
            Self::UnsupportedProtocol => write!(f, "unsupported protocol"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct RawLatest {
    pub version: Version,
    pub players: Players,
    pub description: RawDescription,
    pub favicon: Option<String>,
    #[serde(rename = "enforcesSecureChat")]
    pub enforces_secure_chat: Option<bool>,
    #[serde(rename = "previewsChat")]
    pub previews_chat: Option<bool>,
    #[serde(rename = "modinfo")]
    pub mod_info: Option<ModInfo>,
    #[serde(rename = "forgeData")]
    pub forge_data: Option<ForgeData>,
    #[serde(skip)]
    pub raw_json: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[non_exhaustive]
pub struct Response {
    pub version: String,
    pub protocol: i32,
    pub enforces_secure_chat: Option<bool>,
    pub previews_chat: Option<bool>,
    pub max_players: usize,
    pub online_players: usize,
    pub sample: Option<Vec<Player>>,
    pub description: Chat,
    pub favicon: Option<Vec<u8>>,
    pub mod_info: Option<ModInfo>,
    pub forge_data: Option<ForgeData>,
    #[serde(skip)]
    pub(crate) raw: Vec<u8>,
}

impl Response {
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
}

impl TryFrom<RawLatest> for Response {
    type Error = Error;

    fn try_from(raw: RawLatest) -> Result<Self> {
        let favicon = if let Some(favicon) = raw.favicon {
            let slice = favicon.get(22..).ok_or(Error::UnsupportedProtocol)?;
            Some(
                STANDARD
                    .decode(slice)
                    .map_err(|_| Error::UnsupportedProtocol)?,
            )
        } else {
            None
        };
        Ok(Self {
            version: raw.version.name,
            protocol: raw.version.protocol,
            enforces_secure_chat: raw.enforces_secure_chat,
            previews_chat: raw.previews_chat,
            max_players: raw.players.max,
            online_players: raw.players.online,
            sample: raw.players.sample,
            description: raw.description.into(),
            favicon,
            mod_info: raw.mod_info,
            forge_data: raw.forge_data,
            raw: raw.raw_json,
        })
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct Version {
    pub name: String,
    pub protocol: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct Players {
    pub max: usize,
    pub online: usize,
    pub sample: Option<Vec<Player>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Player {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub(crate) enum RawDescription {
    Raw(String),
    Chat(Chat),
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ModInfo {
    #[serde(rename = "type")]
    pub mod_type: String,
    #[serde(rename = "modList")]
    pub mod_list: Vec<ModInfoItem>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ModInfoItem {
    #[serde(rename = "modid")]
    pub mod_id: String,
    pub version: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForgeData {
    pub channels: Vec<ForgeChannel>,
    pub mods: Vec<ForgeMod>,
    #[serde(rename = "fmlNetworkVersion")]
    pub fml_network_version: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForgeChannel {
    pub res: String,
    pub version: String,
    pub required: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ForgeMod {
    #[serde(rename = "modId")]
    pub mod_id: String,
    #[serde(rename = "modmarker")]
    pub mod_marker: String,
}

#[derive(Deserialize, Serialize, Default, Clone)]
pub struct Chat {
    pub text: String,
    #[serde(default)]
    pub bold: bool,
    #[serde(default)]
    pub italic: bool,
    #[serde(default)]
    pub underlined: bool,
    #[serde(default)]
    pub strikethrough: bool,
    #[serde(default)]
    pub obfuscated: bool,
    pub color: Option<String>,
    #[serde(default)]
    pub extra: Vec<Chat>,
}

impl From<RawDescription> for Chat {
    fn from(description: RawDescription) -> Self {
        match description {
            RawDescription::Chat(chat) => chat,
            RawDescription::Raw(text) => Chat {
                text,
                ..Default::default()
            },
        }
    }
}

impl fmt::Debug for Chat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let text = self.text.replace("\n", "");
        let text = text.split_whitespace().collect::<Vec<&str>>().join(" ");
        write!(f, "{}", text)?;
        for extra in &self.extra {
            write!(f, "{:?}", extra.clone())?;
        }
        Ok(())
    }
}

const LEGACY_REQUEST: [u8; 35] = [
    0xfe, 0x01, 0xfa, 0x00, 0x0b, 0x00, 0x4d, 0x00, 0x43, 0x00, 0x7c, 0x00, 0x50, 0x00, 0x69, 0x00,
    0x6e, 0x00, 0x67, 0x00, 0x48, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x74, 7, 0x4a, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00,
];

const LAST_SEVEN_BITS: i32 = 0b0111_1111;
const NEXT_BYTE_EXISTS: u8 = 0b1000_0000;
const SEVEN_BITS_SHIFT_MASK: i32 = 0x01_ff_ff_ff;

fn write_varint(sink: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut temp = (value & LAST_SEVEN_BITS) as u8;
        value >>= 7;
        value &= SEVEN_BITS_SHIFT_MASK;
        if value != 0 {
            temp |= NEXT_BYTE_EXISTS;
        }
        sink.push(temp);
        if value == 0 {
            break;
        }
    }
}

fn build_latest_request(hostname: &str, port: u16) -> Result<Vec<u8>> {
    let mut buffer = vec![
        0x00,
        0xff,
        0xff,
        0xff,
        0xff,
        0x0f,
    ];
    write_varint(&mut buffer, hostname.len() as i32);
    buffer.extend_from_slice(hostname.as_bytes());
    buffer.extend_from_slice(&[
        (port >> 8) as u8,
        (port & 0b1111_1111) as u8,
        0x01,
    ]);
    let mut full_buffer = vec![];
    write_varint(&mut full_buffer, buffer.len() as i32);
    full_buffer.append(&mut buffer);
    full_buffer.extend_from_slice(&[
        1,
        0x00,
    ]);
    Ok(full_buffer)
}

fn decode_latest_response(buffer: &[u8]) -> Result<RawLatest> {
    serde_json::from_slice(buffer).map_err(|_| Error::UnsupportedProtocol)
}

fn decode_legacy(buffer: &[u8]) -> Result<String> {
    if buffer.len() <= 3 || buffer[0] != 0xff {
        return Err(Error::UnsupportedProtocol);
    }
    let utf16be: Vec<u16> = buffer[3..]
        .chunks_exact(2)
        .map(|chunk| ((chunk[0] as u16) << 8) | chunk[1] as u16)
        .collect();
    String::from_utf16(&utf16be).map_err(|_| Error::UnsupportedProtocol)
}

fn parse_legacy(s: &str, raw: Vec<u8>) -> Result<Response> {
    let mut fields = s.split('\0');
    let magic = fields.next().map(|s| s == "\u{00a7}\u{0031}");
    let protocol = fields.next().and_then(|s| s.parse().ok());
    let version = fields.next();
    let motd = fields.next();
    let players = fields.next().and_then(|s| s.parse().ok());
    let max_players = fields.next().and_then(|s| s.parse().ok());
    match (magic, protocol, version, motd, players, max_players) {
        (
            Some(true),
            Some(protocol),
            Some(version),
            Some(motd),
            Some(players),
            Some(max_players),
        ) => Ok(Response {
            protocol,
            enforces_secure_chat: None,
            previews_chat: None,
            version: version.to_string(),
            description: Chat {
                text: motd.to_string(),
                ..Default::default()
            },
            online_players: players,
            max_players,
            favicon: None,
            forge_data: None,
            mod_info: None,
            sample: None,
            raw,
        }),
        _ => Err(Error::UnsupportedProtocol),
    }
}

fn read_varint(stream: &mut impl Read) -> Result<i32> {
    let mut buffer = [0u8];
    let mut result = 0;
    let mut read_count = 0u32;
    loop {
        stream.read_exact(&mut buffer)?;
        result |= (buffer[0] as i32 & LAST_SEVEN_BITS)
            .checked_shl(7 * read_count)
            .ok_or(Error::UnsupportedProtocol)?;

        read_count += 1;
        if read_count > 5 {
            break Err(Error::UnsupportedProtocol);
        } else if (buffer[0] & NEXT_BYTE_EXISTS) == 0 {
            break Ok(result);
        }
    }
}

fn ping_latest<Stream>(stream: &mut Stream, hostname: &str, port: u16) -> Result<Response>
where
    Stream: Read + Write,
{
    let request = build_latest_request(hostname, port)?;
    stream.write_all(&request)?;
    stream.flush()?;

    let _length = read_varint(stream)?;
    let packet_id = read_varint(stream)?;
    let response_length = read_varint(stream)?;
    if packet_id != 0x00 || response_length < 0 {
        return Err(Error::UnsupportedProtocol);
    }
    let mut response_buffer = vec![0; response_length as usize];
    stream.read_exact(&mut response_buffer)?;

    let mut raw = decode_latest_response(&response_buffer)?;
    raw.raw_json = response_buffer;
    raw.try_into()
}

fn ping_legacy<Stream>(stream: &mut Stream) -> Result<Response>
where
    Stream: Read + Write,
{
    stream.write_all(&LEGACY_REQUEST)?;
    stream.flush()?;

    let mut buffer = Vec::new();
    stream.read_to_end(&mut buffer)?;

    let response = decode_legacy(&buffer)?;
    parse_legacy(&response, buffer)
}

fn ping<Stream>(stream: &mut Stream, hostname: &str, port: u16) -> Result<Response>
where
    Stream: Read + Write,
{
    ping_latest(stream, hostname, port).or_else(|_| ping_legacy(stream))
}

fn resolve_srv(hostname: &str, port: u16) -> (String, u16) {
    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())
        .expect("Failed to create DNS resolver");

    let srv_query = format!("_minecraft._tcp.{}", hostname);
    match resolver.srv_lookup(srv_query) {
        Ok(srv_records) => {
            if let Some(srv) = srv_records.iter().next() {
                println!("SRV record found. Redirecting to {}:{}", srv.target().to_ascii(), srv.port());
                (srv.target().to_ascii(), srv.port())
            } else {
                println!("No SRV record found. Using original hostname and port.");
                (hostname.to_string(), port)
            }
        }
        Err(e) => {
            println!("Error looking up SRV record: {}. Using original hostname and port.", e);
            (hostname.to_string(), port)
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <hostname> <port>", args[0]);
        process::exit(1);
    }

    let hostname = &args[1];
    let port: u16 = match args[2].parse() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Invalid port number");
            process::exit(1);
        }
    };

    println!("Resolving SRV record for {}:{}", hostname, port);
    let (resolved_hostname, resolved_port) = resolve_srv(hostname, port);

    println!("Attempting to ping {}:{}", resolved_hostname, resolved_port);

    match TcpStream::connect((resolved_hostname.as_str(), resolved_port)) {
        Ok(mut stream) => {
            println!("Connected to server. Attempting to ping...");
            match ping(&mut stream, &resolved_hostname, resolved_port) {
                Ok(response) => {
                    println!("Server version: {}", response.version);
                    println!("Protocol: {}", response.protocol);
                    println!("Max players: {}", response.max_players);
                    println!("Online players: {}", response.online_players);
                    println!("Description: {:?}", response.description);
                    if let Some(mod_info) = response.mod_info {
                        println!("Mod type: {}", mod_info.mod_type);
                        println!("Mods: {:?}", mod_info.mod_list);
                    }
                    if let Some(forge_data) = response.forge_data {
                        println!("Forge network version: {}", forge_data.fml_network_version);
                        println!("Forge mods: {:?}", forge_data.mods);
                    }
                }
                Err(Error::UnsupportedProtocol) => {
                    eprintln!("The server is using an unsupported protocol version.");
                    eprintln!("This could be because the server is running a very old or very new version of Minecraft.");
                }
                Err(e) => {
                    eprintln!("Error pinging server: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to connect to server: {}", e);
        }
    }
}
