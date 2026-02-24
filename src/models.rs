use serde::{Deserialize, Serialize};

// OAuth2 Token Response
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Kdf", alias = "kdf")]
    pub kdf: Option<u8>,
    #[serde(alias = "KdfIterations", alias = "kdfIterations")]
    pub kdf_iterations: Option<u32>,
}

// Sync Response - contains all vault data
#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    #[serde(alias = "Ciphers", alias = "ciphers")]
    pub ciphers: Vec<Cipher>,
    #[serde(alias = "Folders", alias = "folders")]
    pub folders: Vec<Folder>,
    #[serde(alias = "Profile", alias = "profile")]
    pub profile: Profile,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    #[serde(alias = "Id", alias = "id")]
    pub id: String,
    #[serde(alias = "Email", alias = "email")]
    pub email: String,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Folder {
    #[serde(alias = "Id", alias = "id")]
    pub id: String,
    #[serde(alias = "Name", alias = "name")]
    pub name: String,
}

// Cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
}

impl std::fmt::Display for CipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherType::Login => write!(f, "login"),
            CipherType::SecureNote => write!(f, "note"),
            CipherType::Card => write!(f, "card"),
            CipherType::Identity => write!(f, "identity"),
        }
    }
}

impl CipherType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "login" | "1" => Some(CipherType::Login),
            "note" | "securenote" | "2" => Some(CipherType::SecureNote),
            "card" | "3" => Some(CipherType::Card),
            "identity" | "4" => Some(CipherType::Identity),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Cipher {
    #[serde(alias = "Id", alias = "id")]
    pub id: String,
    #[serde(alias = "Type", alias = "type")]
    pub r#type: u8,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Notes", alias = "notes")]
    pub notes: Option<String>,
    #[serde(alias = "FolderId", alias = "folderId")]
    pub folder_id: Option<String>,
    #[serde(alias = "Login", alias = "login")]
    pub login: Option<LoginData>,
    #[serde(alias = "Card", alias = "card")]
    pub card: Option<CardData>,
    #[serde(alias = "Identity", alias = "identity")]
    pub identity: Option<IdentityData>,
    #[serde(alias = "SecureNote", alias = "secureNote")]
    pub secure_note: Option<SecureNoteData>,
    #[serde(alias = "Fields", alias = "fields")]
    pub fields: Option<Vec<FieldData>>,
    // Handle nested data structure (Vaultwarden format)
    #[serde(alias = "Data", alias = "data")]
    pub data: Option<CipherData>,
}

// Nested cipher data (Vaultwarden returns data in this nested format)
#[derive(Debug, Clone, Deserialize)]
pub struct CipherData {
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Notes", alias = "notes")]
    pub notes: Option<String>,
    #[serde(alias = "Username", alias = "username")]
    pub username: Option<String>,
    #[serde(alias = "Password", alias = "password")]
    pub password: Option<String>,
    #[serde(alias = "Totp", alias = "totp")]
    pub totp: Option<String>,
    #[serde(alias = "Uri", alias = "uri")]
    pub uri: Option<String>,
    #[serde(alias = "Uris", alias = "uris")]
    pub uris: Option<Vec<UriData>>,
    #[serde(alias = "Fields", alias = "fields")]
    pub fields: Option<Vec<FieldData>>,
}

impl Cipher {
    pub fn cipher_type(&self) -> Option<CipherType> {
        match self.r#type {
            1 => Some(CipherType::Login),
            2 => Some(CipherType::SecureNote),
            3 => Some(CipherType::Card),
            4 => Some(CipherType::Identity),
            _ => None,
        }
    }

    // Get the name from either direct field or nested data
    pub fn get_name(&self) -> Option<&str> {
        self.name.as_deref()
            .or_else(|| self.data.as_ref().and_then(|d| d.name.as_deref()))
    }

    // Get username from login or nested data
    pub fn get_username(&self) -> Option<&str> {
        self.login.as_ref().and_then(|l| l.username.as_deref())
            .or_else(|| self.data.as_ref().and_then(|d| d.username.as_deref()))
    }

    // Get password from login or nested data
    pub fn get_password(&self) -> Option<&str> {
        self.login.as_ref().and_then(|l| l.password.as_deref())
            .or_else(|| self.data.as_ref().and_then(|d| d.password.as_deref()))
    }

    // Get URI from login or nested data
    pub fn get_uri(&self) -> Option<&str> {
        self.login.as_ref()
            .and_then(|l| l.uris.as_ref())
            .and_then(|uris| uris.first())
            .and_then(|u| u.uri.as_deref())
            .or_else(|| self.data.as_ref().and_then(|d| {
                d.uri.as_deref()
                    .or_else(|| d.uris.as_ref()
                        .and_then(|uris| uris.first())
                        .and_then(|u| u.uri.as_deref()))
            }))
    }

    // Get notes
    pub fn get_notes(&self) -> Option<&str> {
        self.notes.as_deref()
            .or_else(|| self.data.as_ref().and_then(|d| d.notes.as_deref()))
    }

    // Get fields
    pub fn get_fields(&self) -> Option<&Vec<FieldData>> {
        self.fields.as_ref()
            .or_else(|| self.data.as_ref().and_then(|d| d.fields.as_ref()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginData {
    #[serde(alias = "Username", alias = "username")]
    pub username: Option<String>,
    #[serde(alias = "Password", alias = "password")]
    pub password: Option<String>,
    #[serde(alias = "Totp", alias = "totp")]
    pub totp: Option<String>,
    #[serde(alias = "Uris", alias = "uris")]
    pub uris: Option<Vec<UriData>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UriData {
    #[serde(alias = "Uri", alias = "uri")]
    pub uri: Option<String>,
    #[serde(alias = "Match", alias = "match")]
    pub r#match: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardData {
    #[serde(alias = "CardholderName", alias = "cardholderName")]
    pub cardholder_name: Option<String>,
    #[serde(alias = "Brand", alias = "brand")]
    pub brand: Option<String>,
    #[serde(alias = "Number", alias = "number")]
    pub number: Option<String>,
    #[serde(alias = "ExpMonth", alias = "expMonth")]
    pub exp_month: Option<String>,
    #[serde(alias = "ExpYear", alias = "expYear")]
    pub exp_year: Option<String>,
    #[serde(alias = "Code", alias = "code")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityData {
    #[serde(alias = "Title", alias = "title")]
    pub title: Option<String>,
    #[serde(alias = "FirstName", alias = "firstName")]
    pub first_name: Option<String>,
    #[serde(alias = "MiddleName", alias = "middleName")]
    pub middle_name: Option<String>,
    #[serde(alias = "LastName", alias = "lastName")]
    pub last_name: Option<String>,
    #[serde(alias = "Email", alias = "email")]
    pub email: Option<String>,
    #[serde(alias = "Phone", alias = "phone")]
    pub phone: Option<String>,
    #[serde(alias = "Company", alias = "company")]
    pub company: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecureNoteData {
    #[serde(alias = "Type", alias = "type")]
    pub r#type: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldData {
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Value", alias = "value")]
    pub value: Option<String>,
    #[serde(alias = "Type", alias = "type")]
    pub r#type: u8, // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
}

// Simplified cipher output for display (decrypted)
#[derive(Debug, Clone, Serialize)]
pub struct CipherOutput {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<FieldOutput>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldOutput {
    pub name: String,
    pub value: String,
    pub hidden: bool,
}
