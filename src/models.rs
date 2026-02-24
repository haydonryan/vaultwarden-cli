use serde::{Deserialize, Serialize};

// OAuth2 Token Response
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: i64,
    pub token_type: String,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "Key")]
    pub key: Option<String>,
    #[serde(rename = "PrivateKey")]
    pub private_key: Option<String>,
}

// Sync Response - contains all vault data
#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponse {
    #[serde(rename = "Ciphers")]
    pub ciphers: Vec<Cipher>,
    #[serde(rename = "Folders")]
    pub folders: Vec<Folder>,
    #[serde(rename = "Profile")]
    pub profile: Profile,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Email")]
    pub email: String,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Key")]
    pub key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Folder {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Name")]
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
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Type")]
    pub r#type: u8,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
    #[serde(rename = "FolderId")]
    pub folder_id: Option<String>,
    #[serde(rename = "Login")]
    pub login: Option<LoginData>,
    #[serde(rename = "Card")]
    pub card: Option<CardData>,
    #[serde(rename = "Identity")]
    pub identity: Option<IdentityData>,
    #[serde(rename = "SecureNote")]
    pub secure_note: Option<SecureNoteData>,
    #[serde(rename = "Fields")]
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

    pub fn matches_search(&self, search: &str) -> bool {
        let search_lower = search.to_lowercase();

        // Check name
        if self.name.to_lowercase().contains(&search_lower) {
            return true;
        }

        // Check login URIs
        if let Some(login) = &self.login {
            if let Some(uris) = &login.uris {
                for uri in uris {
                    if let Some(u) = &uri.uri {
                        if u.to_lowercase().contains(&search_lower) {
                            return true;
                        }
                    }
                }
            }
            if let Some(username) = &login.username {
                if username.to_lowercase().contains(&search_lower) {
                    return true;
                }
            }
        }

        false
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginData {
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Password")]
    pub password: Option<String>,
    #[serde(rename = "Totp")]
    pub totp: Option<String>,
    #[serde(rename = "Uris")]
    pub uris: Option<Vec<UriData>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UriData {
    #[serde(rename = "Uri")]
    pub uri: Option<String>,
    #[serde(rename = "Match")]
    pub r#match: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CardData {
    #[serde(rename = "CardholderName")]
    pub cardholder_name: Option<String>,
    #[serde(rename = "Brand")]
    pub brand: Option<String>,
    #[serde(rename = "Number")]
    pub number: Option<String>,
    #[serde(rename = "ExpMonth")]
    pub exp_month: Option<String>,
    #[serde(rename = "ExpYear")]
    pub exp_year: Option<String>,
    #[serde(rename = "Code")]
    pub code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityData {
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "FirstName")]
    pub first_name: Option<String>,
    #[serde(rename = "MiddleName")]
    pub middle_name: Option<String>,
    #[serde(rename = "LastName")]
    pub last_name: Option<String>,
    #[serde(rename = "Email")]
    pub email: Option<String>,
    #[serde(rename = "Phone")]
    pub phone: Option<String>,
    #[serde(rename = "Company")]
    pub company: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecureNoteData {
    #[serde(rename = "Type")]
    pub r#type: Option<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldData {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Value")]
    pub value: Option<String>,
    #[serde(rename = "Type")]
    pub r#type: u8, // 0=Text, 1=Hidden, 2=Boolean, 3=Linked
}

// Simplified cipher output for display
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

impl From<&Cipher> for CipherOutput {
    fn from(cipher: &Cipher) -> Self {
        let (username, password, uri) = if let Some(login) = &cipher.login {
            (
                login.username.clone(),
                login.password.clone(),
                login.uris.as_ref().and_then(|u| u.first().and_then(|uri| uri.uri.clone())),
            )
        } else {
            (None, None, None)
        };

        let fields = cipher.fields.as_ref().map(|fields| {
            fields
                .iter()
                .filter_map(|f| {
                    Some(FieldOutput {
                        name: f.name.clone()?,
                        value: f.value.clone().unwrap_or_default(),
                        hidden: f.r#type == 1,
                    })
                })
                .collect()
        });

        CipherOutput {
            id: cipher.id.clone(),
            cipher_type: cipher.cipher_type().map(|t| t.to_string()).unwrap_or_else(|| "unknown".to_string()),
            name: cipher.name.clone(),
            username,
            password,
            uri,
            notes: cipher.notes.clone(),
            fields,
        }
    }
}
