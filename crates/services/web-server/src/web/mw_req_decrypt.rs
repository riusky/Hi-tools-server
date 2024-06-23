use crate::web::Result;
use axum::body::Body;
use axum::body::Bytes;
use http_body_util::BodyExt;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use tracing::debug;
use serde::Serialize;
use serde_json::Value;


pub async fn mw_req_decrypt_resolver(
	req: Request<Body>,
	next: Next,
) -> Result<Response> {
	debug!("{:<12} - mw_req_decrypt_resolver", "MIDDLEWARE");

	let (parts, body) = req.into_parts();
    let bytes = req_decrypt(body).await?;

	let req = Request::from_parts(parts, Body::from(bytes));
	Ok(next.run(req).await)

}

async fn req_decrypt<B>(body: B) -> BytesExtResult
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = body.collect().await.map_err(|_| DecryptExtError::DecryptError)?.to_bytes();

    let body_str = std::str::from_utf8(&bytes).map_err(|_| DecryptExtError::DecryptError)?;

    let json_value:Value = serde_json::from_str(body_str).map_err(|_| DecryptExtError::DecryptError)?;
    
    println!("Valid JSON: {:?}", json_value);

    if let Some(pwd) = json_value.get("pwd") {
        println!("pwd: {}", pwd);
    }

    Ok(bytes)
}



// region:    --- Ctx Extractor Result/Error
type BytesExtResult = core::result::Result<Bytes, DecryptExtError>;

#[derive(Clone, Serialize, Debug)]
pub enum DecryptExtError {
	DecryptError,
}
// endregion: --- Ctx Extractor Result/Error