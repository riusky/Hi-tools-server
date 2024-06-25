use lib_utils::envs::{get_env_b64u_as_u8s, get_env_parse};
use std::sync::OnceLock;

pub fn rsa_config() -> &'static RsaConfig {
	static INSTANCE: OnceLock<RsaConfig> = OnceLock::new();

	INSTANCE.get_or_init(|| {
		RsaConfig::load_from_env().unwrap_or_else(|ex| {
			panic!("FATAL - WHILE LOADING CONF - Cause: {ex:?}")
		})
	})
}

#[allow(non_snake_case)]
pub struct RsaConfig {
	// -- Crypt
	pub PUBLIC_KEY: Vec<u8>,

	pub PRIVATE_KEY: Vec<u8>,
}

impl RsaConfig {
	fn load_from_env() -> lib_utils::envs::Result<RsaConfig> {
		Ok(RsaConfig {
			// -- Crypt
			PUBLIC_KEY: get_env_b64u_as_u8s("PUBLIC_KEY")?,

			PRIVATE_KEY: get_env_b64u_as_u8s("PRIVATE_KEY")?,
		})
	}
}
