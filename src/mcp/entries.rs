use crate::{
    core::{
        limits::{MAX_DESCRIPTION_BYTES, MAX_PASSWORD_BYTES, MIN_ACCOUNT_PASSWORD_LENGTH},
        password::{Password, PasswordCharset},
        types::decode_secret_text,
        validation::Validation,
    },
    mcp::{
        config::{McpConfig, McpPermission},
        guard::McpGuard,
    },
};
use regex::RegexBuilder;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const REGEX_SIZE_LIMIT_BYTES: usize = 1024 * 1024;
const DEFAULT_GENERATED_LENGTH: usize = 20;

pub struct McpEntries;

impl McpEntries {
    pub fn list(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_read(perm)?;
        let (account_name, storage, crypto) = McpGuard::open_vault(config, perm, args)?;

        let entries = storage.list_entries().map_err(|e| e.to_string())?;
        let mut items = Vec::with_capacity(entries.len());

        for (name, entry) in entries {
            let description = crypto
                .decrypt_description(&name, &entry)
                .map_err(|e| e.to_string())?;
            let tags = crypto
                .decrypt_tags(&name, &entry)
                .map_err(|e| e.to_string())?;
            items.push(json!({
                "name": name,
                "description": description,
                "tags": tags
            }));
        }

        let payload = json!({
            "account": account_name,
            "count": items.len(),
            "entries": items
        });
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
    }

    pub fn get(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_read(perm)?;
        let name = McpGuard::required_str(args, "name")?;
        let (account_name, storage, crypto) = McpGuard::open_vault(config, perm, args)?;

        let entry = storage
            .get_password(&name)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("Entry '{name}' not found in account '{account_name}'."))?;

        let decrypted = crypto
            .decrypt_entry(&name, &entry)
            .map_err(|e| e.to_string())?;
        let password = Zeroizing::new(decode_secret_text(decrypted).map_err(|e| e.to_string())?);
        let description = crypto
            .decrypt_description(&name, &entry)
            .map_err(|e| e.to_string())?;
        let tags = crypto
            .decrypt_tags(&name, &entry)
            .map_err(|e| e.to_string())?;

        let payload = json!({
            "account": account_name,
            "name": name,
            "password": password.as_str(),
            "description": description,
            "tags": tags
        });
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
    }

    pub fn search(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_read(perm)?;
        let pattern = McpGuard::required_str(args, "pattern")?;
        let ignore_case = args
            .get("ignore_case")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let names_only = args
            .get("names_only")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let (account_name, storage, crypto) = McpGuard::open_vault(config, perm, args)?;
        let entries = storage
            .search_entries(&pattern)
            .map_err(|e| e.to_string())?;

        let regex = RegexBuilder::new(&pattern)
            .case_insensitive(ignore_case)
            .size_limit(REGEX_SIZE_LIMIT_BYTES)
            .build()
            .map_err(|e| format!("Invalid search pattern: {e}"))?;

        let mut matches = Vec::new();
        for (name, entry) in entries {
            let name_matched = regex.is_match(&name);
            let description = if names_only {
                None
            } else {
                crypto.decrypt_description(&name, &entry).ok().flatten()
            };
            let desc_matched = description.as_deref().is_some_and(|d| regex.is_match(d));
            let tags = crypto.decrypt_tags(&name, &entry).unwrap_or_default();
            let tag_matched = !names_only && tags.iter().any(|t| regex.is_match(t));

            if name_matched || desc_matched || tag_matched {
                matches.push(json!({
                    "name": name,
                    "description": description,
                    "tags": tags
                }));
            }
        }

        let payload = json!({
            "account": account_name,
            "count": matches.len(),
            "matches": matches
        });
        serde_json::to_string_pretty(&payload).map_err(|e| e.to_string())
    }

    pub fn create(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_write(perm)?;
        let name = McpGuard::required_str(args, "name")?;
        Validation::check_account_name(&name)?;

        let (account_name, storage, crypto) = McpGuard::open_vault(config, perm, args)?;

        if storage.entry_exists(&name).map_err(|e| e.to_string())? {
            return Err(format!(
                "Entry '{name}' already exists in account '{account_name}'."
            ));
        }

        let password = Self::resolve_new_password(args)?;
        let description = args
            .get("description")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if let Some(desc) = description {
            if desc.len() > MAX_DESCRIPTION_BYTES {
                return Err(format!("Description exceeds {MAX_DESCRIPTION_BYTES} bytes"));
            }
            Validation::check_description_text(desc)?;
            Password::in_desc_check(password.as_str(), desc).map_err(|e| e.to_string())?;
        }

        let tag_list = McpGuard::extract_tags(args)?;
        let entry = crypto
            .create_entry(&name, password.as_bytes(), description, tag_list.as_deref())
            .map_err(|e| e.to_string())?;

        if !storage
            .create_password(&name, &entry)
            .map_err(|e| e.to_string())?
        {
            return Err(format!(
                "Entry '{name}' already exists in account '{account_name}'."
            ));
        }

        Ok(format!(
            "Created entry '{name}' in account '{account_name}'."
        ))
    }

    pub fn edit(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_write(perm)?;
        let name = McpGuard::required_str(args, "name")?;
        if Validation::is_reserved_or_blank(&name) {
            return Err("Cannot edit system or empty entries".to_string());
        }

        let (account_name, storage, crypto) = McpGuard::open_vault(config, perm, args)?;
        let existing = storage
            .get_password(&name)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("Entry '{name}' not found in account '{account_name}'."))?;

        let current_password = Zeroizing::new(
            decode_secret_text(
                crypto
                    .decrypt_entry(&name, &existing)
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?,
        );
        let current_description = crypto
            .decrypt_description(&name, &existing)
            .map_err(|e| e.to_string())?;
        let current_tags = crypto
            .decrypt_tags(&name, &existing)
            .map_err(|e| e.to_string())?;

        let new_password = if let Some(raw) = args
            .get("password")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            if raw.len() > MAX_PASSWORD_BYTES {
                return Err(format!("Password exceeds {MAX_PASSWORD_BYTES} bytes"));
            }
            Password::length_check(raw, MIN_ACCOUNT_PASSWORD_LENGTH).map_err(|e| e.to_string())?;
            Zeroizing::new(raw.to_string())
        } else {
            current_password
        };

        let new_description = if let Some(raw) = args.get("description").and_then(Value::as_str) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                if trimmed.len() > MAX_DESCRIPTION_BYTES {
                    return Err(format!("Description exceeds {MAX_DESCRIPTION_BYTES} bytes"));
                }
                Validation::check_description_text(trimmed)?;
                Some(trimmed.to_string())
            }
        } else {
            current_description
        };

        if let Some(desc) = new_description.as_deref() {
            Password::in_desc_check(new_password.as_str(), desc).map_err(|e| e.to_string())?;
        }

        let new_tags = if let Some(tags) = McpGuard::extract_tags(args)? {
            Some(tags)
        } else {
            (!current_tags.is_empty()).then_some(current_tags)
        };

        let updated = crypto
            .create_entry(
                &name,
                new_password.as_bytes(),
                new_description.as_deref(),
                new_tags.as_deref(),
            )
            .map_err(|e| e.to_string())?;

        if !storage
            .edit_password(&name, &updated)
            .map_err(|e| e.to_string())?
        {
            return Err(format!(
                "Entry '{name}' not found in account '{account_name}'."
            ));
        }

        Ok(format!(
            "Updated entry '{name}' in account '{account_name}'."
        ))
    }

    pub fn delete(config: &McpConfig, perm: McpPermission, args: &Value) -> Result<String, String> {
        McpGuard::require_write(perm)?;
        let name = McpGuard::required_str(args, "name")?;
        if Validation::is_reserved_or_blank(&name) {
            return Err("Cannot delete system or empty entries".to_string());
        }

        let (account_name, storage, _) = McpGuard::open_vault(config, perm, args)?;
        if !storage.delete_password(&name).map_err(|e| e.to_string())? {
            return Err(format!(
                "Entry '{name}' not found in account '{account_name}'."
            ));
        }

        Ok(format!(
            "Deleted entry '{name}' from account '{account_name}'."
        ))
    }

    fn resolve_new_password(args: &Value) -> Result<Zeroizing<String>, String> {
        if let Some(raw) = args
            .get("password")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            if raw.len() > MAX_PASSWORD_BYTES {
                return Err(format!("Password exceeds {MAX_PASSWORD_BYTES} bytes"));
            }
            Password::length_check(raw, MIN_ACCOUNT_PASSWORD_LENGTH).map_err(|e| e.to_string())?;
            Ok(Zeroizing::new(raw.to_string()))
        } else {
            let length = match args.get("length").and_then(Value::as_u64) {
                Some(n) => usize::try_from(n).map_err(|_| {
                    format!(
                        "Generated password length must be between {MIN_ACCOUNT_PASSWORD_LENGTH} and {MAX_PASSWORD_BYTES}"
                    )
                })?,
                None => DEFAULT_GENERATED_LENGTH,
            };
            if !(MIN_ACCOUNT_PASSWORD_LENGTH..=MAX_PASSWORD_BYTES).contains(&length) {
                return Err(format!(
                    "Generated password length must be between {MIN_ACCOUNT_PASSWORD_LENGTH} and {MAX_PASSWORD_BYTES}"
                ));
            }
            let charset = PasswordCharset::from_bits(
                PasswordCharset::UPPERCASE
                    | PasswordCharset::LOWERCASE
                    | PasswordCharset::DIGITS
                    | PasswordCharset::SPECIAL,
            );
            Ok(Zeroizing::new(Password::generate(length, charset)?))
        }
    }
}
