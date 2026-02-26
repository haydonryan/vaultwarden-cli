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
pub struct Organization {
    #[serde(alias = "Id", alias = "id")]
    pub id: String,
    #[serde(alias = "Name", alias = "name")]
    pub name: Option<String>,
    #[serde(alias = "Key", alias = "key")]
    pub key: Option<String>,
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
    #[serde(alias = "PrivateKey", alias = "privateKey")]
    pub private_key: Option<String>,
    #[serde(alias = "Organizations", alias = "organizations", default)]
    pub organizations: Vec<Organization>,
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
    #[serde(alias = "OrganizationId", alias = "organizationId")]
    pub organization_id: Option<String>,
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
        self.name
            .as_deref()
            .or_else(|| self.data.as_ref().and_then(|d| d.name.as_deref()))
    }

    // Get username from login or nested data
    pub fn get_username(&self) -> Option<&str> {
        self.login
            .as_ref()
            .and_then(|l| l.username.as_deref())
            .or_else(|| self.data.as_ref().and_then(|d| d.username.as_deref()))
    }

    // Get password from login or nested data
    pub fn get_password(&self) -> Option<&str> {
        self.login
            .as_ref()
            .and_then(|l| l.password.as_deref())
            .or_else(|| self.data.as_ref().and_then(|d| d.password.as_deref()))
    }

    // Get URI from login or nested data
    pub fn get_uri(&self) -> Option<&str> {
        self.login
            .as_ref()
            .and_then(|l| l.uris.as_ref())
            .and_then(|uris| uris.first())
            .and_then(|u| u.uri.as_deref())
            .or_else(|| {
                self.data.as_ref().and_then(|d| {
                    d.uri.as_deref().or_else(|| {
                        d.uris
                            .as_ref()
                            .and_then(|uris| uris.first())
                            .and_then(|u| u.uri.as_deref())
                    })
                })
            })
    }

    // Get notes
    pub fn get_notes(&self) -> Option<&str> {
        self.notes
            .as_deref()
            .or_else(|| self.data.as_ref().and_then(|d| d.notes.as_deref()))
    }

    // Get fields
    pub fn get_fields(&self) -> Option<&Vec<FieldData>> {
        self.fields
            .as_ref()
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

#[cfg(test)]
mod tests {
    use super::*;

    // CipherType tests
    mod cipher_type_tests {
        use super::*;

        #[test]
        fn test_cipher_type_display() {
            assert_eq!(CipherType::Login.to_string(), "login");
            assert_eq!(CipherType::SecureNote.to_string(), "note");
            assert_eq!(CipherType::Card.to_string(), "card");
            assert_eq!(CipherType::Identity.to_string(), "identity");
        }

        #[test]
        fn test_cipher_type_from_str_login() {
            assert_eq!(CipherType::from_str("login"), Some(CipherType::Login));
            assert_eq!(CipherType::from_str("LOGIN"), Some(CipherType::Login));
            assert_eq!(CipherType::from_str("Login"), Some(CipherType::Login));
            assert_eq!(CipherType::from_str("1"), Some(CipherType::Login));
        }

        #[test]
        fn test_cipher_type_from_str_note() {
            assert_eq!(CipherType::from_str("note"), Some(CipherType::SecureNote));
            assert_eq!(CipherType::from_str("NOTE"), Some(CipherType::SecureNote));
            assert_eq!(
                CipherType::from_str("securenote"),
                Some(CipherType::SecureNote)
            );
            assert_eq!(
                CipherType::from_str("SecureNote"),
                Some(CipherType::SecureNote)
            );
            assert_eq!(CipherType::from_str("2"), Some(CipherType::SecureNote));
        }

        #[test]
        fn test_cipher_type_from_str_card() {
            assert_eq!(CipherType::from_str("card"), Some(CipherType::Card));
            assert_eq!(CipherType::from_str("CARD"), Some(CipherType::Card));
            assert_eq!(CipherType::from_str("Card"), Some(CipherType::Card));
            assert_eq!(CipherType::from_str("3"), Some(CipherType::Card));
        }

        #[test]
        fn test_cipher_type_from_str_identity() {
            assert_eq!(CipherType::from_str("identity"), Some(CipherType::Identity));
            assert_eq!(CipherType::from_str("IDENTITY"), Some(CipherType::Identity));
            assert_eq!(CipherType::from_str("Identity"), Some(CipherType::Identity));
            assert_eq!(CipherType::from_str("4"), Some(CipherType::Identity));
        }

        #[test]
        fn test_cipher_type_from_str_invalid() {
            assert_eq!(CipherType::from_str("invalid"), None);
            assert_eq!(CipherType::from_str(""), None);
            assert_eq!(CipherType::from_str("0"), None);
            assert_eq!(CipherType::from_str("5"), None);
            assert_eq!(CipherType::from_str("password"), None);
        }

        #[test]
        fn test_cipher_type_values() {
            assert_eq!(CipherType::Login as u8, 1);
            assert_eq!(CipherType::SecureNote as u8, 2);
            assert_eq!(CipherType::Card as u8, 3);
            assert_eq!(CipherType::Identity as u8, 4);
        }
    }

    // Cipher tests
    mod cipher_tests {
        use super::*;

        fn create_test_cipher() -> Cipher {
            Cipher {
                id: "test-id".to_string(),
                r#type: 1,
                organization_id: None,
                name: Some("encrypted-name".to_string()),
                notes: Some("encrypted-notes".to_string()),
                folder_id: None,
                login: Some(LoginData {
                    username: Some("encrypted-username".to_string()),
                    password: Some("encrypted-password".to_string()),
                    totp: None,
                    uris: Some(vec![UriData {
                        uri: Some("encrypted-uri".to_string()),
                        r#match: None,
                    }]),
                }),
                card: None,
                identity: None,
                secure_note: None,
                fields: Some(vec![FieldData {
                    name: Some("field-name".to_string()),
                    value: Some("field-value".to_string()),
                    r#type: 0,
                }]),
                data: None,
            }
        }

        fn create_cipher_with_nested_data() -> Cipher {
            Cipher {
                id: "test-id".to_string(),
                r#type: 1,
                organization_id: None,
                name: None,
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                fields: None,
                data: Some(CipherData {
                    name: Some("nested-name".to_string()),
                    notes: Some("nested-notes".to_string()),
                    username: Some("nested-username".to_string()),
                    password: Some("nested-password".to_string()),
                    totp: None,
                    uri: Some("nested-uri".to_string()),
                    uris: None,
                    fields: Some(vec![FieldData {
                        name: Some("nested-field".to_string()),
                        value: Some("nested-value".to_string()),
                        r#type: 1,
                    }]),
                }),
            }
        }

        #[test]
        fn test_cipher_type_method() {
            let mut cipher = create_test_cipher();

            cipher.r#type = 1;
            assert_eq!(cipher.cipher_type(), Some(CipherType::Login));

            cipher.r#type = 2;
            assert_eq!(cipher.cipher_type(), Some(CipherType::SecureNote));

            cipher.r#type = 3;
            assert_eq!(cipher.cipher_type(), Some(CipherType::Card));

            cipher.r#type = 4;
            assert_eq!(cipher.cipher_type(), Some(CipherType::Identity));

            cipher.r#type = 99;
            assert_eq!(cipher.cipher_type(), None);
        }

        #[test]
        fn test_get_name_from_direct_field() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_name(), Some("encrypted-name"));
        }

        #[test]
        fn test_get_name_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_name(), Some("nested-name"));
        }

        #[test]
        fn test_get_name_prefers_direct_over_nested() {
            let mut cipher = create_cipher_with_nested_data();
            cipher.name = Some("direct-name".to_string());
            assert_eq!(cipher.get_name(), Some("direct-name"));
        }

        #[test]
        fn test_get_name_none() {
            let cipher = Cipher {
                id: "test".to_string(),
                r#type: 1,
                organization_id: None,
                name: None,
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                fields: None,
                data: None,
            };
            assert_eq!(cipher.get_name(), None);
        }

        #[test]
        fn test_get_username_from_login() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_username(), Some("encrypted-username"));
        }

        #[test]
        fn test_get_username_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_username(), Some("nested-username"));
        }

        #[test]
        fn test_get_password_from_login() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_password(), Some("encrypted-password"));
        }

        #[test]
        fn test_get_password_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_password(), Some("nested-password"));
        }

        #[test]
        fn test_get_uri_from_login_uris() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_uri(), Some("encrypted-uri"));
        }

        #[test]
        fn test_get_uri_from_nested_data_direct() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_uri(), Some("nested-uri"));
        }

        #[test]
        fn test_get_uri_from_nested_uris_array() {
            let cipher = Cipher {
                id: "test".to_string(),
                r#type: 1,
                organization_id: None,
                name: None,
                notes: None,
                folder_id: None,
                login: None,
                card: None,
                identity: None,
                secure_note: None,
                fields: None,
                data: Some(CipherData {
                    name: None,
                    notes: None,
                    username: None,
                    password: None,
                    totp: None,
                    uri: None,
                    uris: Some(vec![UriData {
                        uri: Some("uri-from-array".to_string()),
                        r#match: None,
                    }]),
                    fields: None,
                }),
            };
            assert_eq!(cipher.get_uri(), Some("uri-from-array"));
        }

        #[test]
        fn test_get_notes_from_direct_field() {
            let cipher = create_test_cipher();
            assert_eq!(cipher.get_notes(), Some("encrypted-notes"));
        }

        #[test]
        fn test_get_notes_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            assert_eq!(cipher.get_notes(), Some("nested-notes"));
        }

        #[test]
        fn test_get_fields_from_direct() {
            let cipher = create_test_cipher();
            let fields = cipher.get_fields().unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name, Some("field-name".to_string()));
        }

        #[test]
        fn test_get_fields_from_nested_data() {
            let cipher = create_cipher_with_nested_data();
            let fields = cipher.get_fields().unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0].name, Some("nested-field".to_string()));
        }
    }

    // Deserialization tests
    mod deserialization_tests {
        use super::*;

        #[test]
        fn test_token_response_deserialization() {
            let json = r#"{
                "access_token": "test-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "refresh_token": "refresh-token",
                "Key": "encrypted-key",
                "KdfIterations": 600000
            }"#;

            let response: TokenResponse = serde_json::from_str(json).unwrap();
            assert_eq!(response.access_token, "test-token");
            assert_eq!(response.expires_in, 3600);
            assert_eq!(response.token_type, "Bearer");
            assert_eq!(response.refresh_token, Some("refresh-token".to_string()));
            assert_eq!(response.key, Some("encrypted-key".to_string()));
            assert_eq!(response.kdf_iterations, Some(600000));
        }

        #[test]
        fn test_token_response_lowercase_aliases() {
            let json = r#"{
                "access_token": "test-token",
                "expires_in": 3600,
                "token_type": "Bearer",
                "key": "encrypted-key",
                "kdfIterations": 100000
            }"#;

            let response: TokenResponse = serde_json::from_str(json).unwrap();
            assert_eq!(response.key, Some("encrypted-key".to_string()));
            assert_eq!(response.kdf_iterations, Some(100000));
        }

        #[test]
        fn test_cipher_deserialization_with_login() {
            let json = r#"{
                "Id": "cipher-123",
                "Type": 1,
                "Name": "My Login",
                "Login": {
                    "Username": "user@example.com",
                    "Password": "secret123",
                    "Uris": [
                        {"Uri": "https://example.com", "Match": 0}
                    ]
                }
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(cipher.id, "cipher-123");
            assert_eq!(cipher.r#type, 1);
            assert_eq!(cipher.get_name(), Some("My Login"));
            assert_eq!(cipher.get_username(), Some("user@example.com"));
            assert_eq!(cipher.get_password(), Some("secret123"));
            assert_eq!(cipher.get_uri(), Some("https://example.com"));
        }

        #[test]
        fn test_cipher_deserialization_with_nested_data() {
            let json = r#"{
                "id": "cipher-456",
                "type": 1,
                "data": {
                    "name": "Nested Login",
                    "username": "nested@example.com",
                    "password": "nestedpass",
                    "uri": "https://nested.com"
                }
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(cipher.id, "cipher-456");
            assert_eq!(cipher.get_name(), Some("Nested Login"));
            assert_eq!(cipher.get_username(), Some("nested@example.com"));
            assert_eq!(cipher.get_uri(), Some("https://nested.com"));
        }

        #[test]
        fn test_cipher_deserialization_with_organization() {
            let json = r#"{
                "Id": "cipher-789",
                "Type": 1,
                "OrganizationId": "org-123",
                "Name": "Org Item"
            }"#;

            let cipher: Cipher = serde_json::from_str(json).unwrap();
            assert_eq!(cipher.organization_id, Some("org-123".to_string()));
        }

        #[test]
        fn test_sync_response_deserialization() {
            let json = r#"{
                "Ciphers": [],
                "Folders": [],
                "Profile": {
                    "Id": "user-123",
                    "Email": "user@example.com",
                    "Name": "Test User",
                    "Organizations": []
                }
            }"#;

            let response: SyncResponse = serde_json::from_str(json).unwrap();
            assert!(response.ciphers.is_empty());
            assert!(response.folders.is_empty());
            assert_eq!(response.profile.email, "user@example.com");
        }

        #[test]
        fn test_profile_with_organizations() {
            let json = r#"{
                "Id": "user-123",
                "Email": "user@example.com",
                "Organizations": [
                    {"Id": "org-1", "Name": "Org One", "Key": "org-key-1"},
                    {"Id": "org-2", "Name": "Org Two", "Key": "org-key-2"}
                ]
            }"#;

            let profile: Profile = serde_json::from_str(json).unwrap();
            assert_eq!(profile.organizations.len(), 2);
            assert_eq!(profile.organizations[0].id, "org-1");
            assert_eq!(profile.organizations[1].key, Some("org-key-2".to_string()));
        }

        #[test]
        fn test_field_data_types() {
            let json = r#"[
                {"Name": "text-field", "Value": "text-value", "Type": 0},
                {"Name": "hidden-field", "Value": "hidden-value", "Type": 1},
                {"Name": "bool-field", "Value": "true", "Type": 2},
                {"Name": "linked-field", "Value": "linked", "Type": 3}
            ]"#;

            let fields: Vec<FieldData> = serde_json::from_str(json).unwrap();
            assert_eq!(fields.len(), 4);
            assert_eq!(fields[0].r#type, 0); // Text
            assert_eq!(fields[1].r#type, 1); // Hidden
            assert_eq!(fields[2].r#type, 2); // Boolean
            assert_eq!(fields[3].r#type, 3); // Linked
        }

        #[test]
        fn test_card_data_deserialization() {
            let json = r#"{
                "CardholderName": "John Doe",
                "Brand": "Visa",
                "Number": "4111111111111111",
                "ExpMonth": "12",
                "ExpYear": "2025",
                "Code": "123"
            }"#;

            let card: CardData = serde_json::from_str(json).unwrap();
            assert_eq!(card.cardholder_name, Some("John Doe".to_string()));
            assert_eq!(card.brand, Some("Visa".to_string()));
            assert_eq!(card.code, Some("123".to_string()));
        }

        #[test]
        fn test_identity_data_deserialization() {
            let json = r#"{
                "Title": "Mr",
                "FirstName": "John",
                "LastName": "Doe",
                "Email": "john@example.com",
                "Phone": "555-1234"
            }"#;

            let identity: IdentityData = serde_json::from_str(json).unwrap();
            assert_eq!(identity.title, Some("Mr".to_string()));
            assert_eq!(identity.first_name, Some("John".to_string()));
            assert_eq!(identity.email, Some("john@example.com".to_string()));
        }
    }

    // Serialization tests
    mod serialization_tests {
        use super::*;

        #[test]
        fn test_cipher_output_serialization() {
            let output = CipherOutput {
                id: "test-id".to_string(),
                cipher_type: "login".to_string(),
                name: "Test Login".to_string(),
                username: Some("user@example.com".to_string()),
                password: Some("secret".to_string()),
                uri: Some("https://example.com".to_string()),
                notes: None,
                fields: None,
            };

            let json = serde_json::to_string(&output).unwrap();
            assert!(json.contains("\"id\":\"test-id\""));
            assert!(json.contains("\"type\":\"login\"")); // Note: uses "type" due to rename
            assert!(json.contains("\"username\":\"user@example.com\""));
            // Notes should be skipped because it's None
            assert!(!json.contains("\"notes\""));
        }

        #[test]
        fn test_cipher_output_with_fields() {
            let output = CipherOutput {
                id: "test-id".to_string(),
                cipher_type: "login".to_string(),
                name: "Test".to_string(),
                username: None,
                password: None,
                uri: None,
                notes: None,
                fields: Some(vec![FieldOutput {
                    name: "api-key".to_string(),
                    value: "secret-key".to_string(),
                    hidden: true,
                }]),
            };

            let json = serde_json::to_string(&output).unwrap();
            assert!(json.contains("\"fields\""));
            assert!(json.contains("\"api-key\""));
            assert!(json.contains("\"hidden\":true"));
        }

        #[test]
        fn test_cipher_type_serialization() {
            // CipherType with repr(u8) serializes to numbers
            let cipher_type = CipherType::Login;
            let json = serde_json::to_string(&cipher_type).unwrap();
            // Should be either "Login" (string) or a number representation
            assert!(json == "\"Login\"" || json == "1");

            // Test that we can deserialize CipherType from a struct context
            // (as it comes from the API in a Cipher object)
            let cipher_json = r#"{"Id": "test", "Type": 1}"#;
            let cipher: Cipher = serde_json::from_str(cipher_json).unwrap();
            assert_eq!(cipher.cipher_type(), Some(CipherType::Login));
        }
    }
}
