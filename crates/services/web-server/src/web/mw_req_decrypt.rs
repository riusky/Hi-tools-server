//! 该模块提供了用于解密加密请求体并处理错误的中间件。
//!
//! `mw_req_decrypt_resolver` 函数负责使用 `req_decrypt` 解密请求体，验证和处理加密数据，并将解密后的请求传递给下一个中间件或处理函数。
//! 如果解密或验证失败，它将返回适当的错误响应。
//!
//! # 错误
//!
//! 该模块定义了几种错误类型，用于表示不同的解密和处理失败情况：
//!
//! - `DecryptExtError::DecryptError`: 表示一般解密错误。
//! - `DecryptExtError::JsonError`: 表示与 JSON 解析或序列化相关的错误。
//! - `DecryptExtError::VerificationError`: 表示数据验证期间的错误。
//!
//! # 示例
//!
//! ```
//! use axum::{body::Body, response::Response, Router};
//! use my_middleware::{mw_req_decrypt_resolver, DecryptExtError};
//!
//! async fn handler() -> &'static str {
//!     "Hello, world!"
//! }
//!
//! let app = Router::new()
//!     .route("/api", axum::post(handler).layer(mw_req_decrypt_resolver));
//! ```

use axum::{
    body::{Body, Bytes},
    http::Request,
    response::Response,
    middleware::Next,
};
use crate::web::Result;
use http_body_util::BodyExt; // 用于简化 body 操作
use lib_decrypt::model; // 假设这里定义了 EncryptedData
use serde::Serialize; // Serialize
use tracing::debug; // 用于调试日志

/// 解密加密的 HTTP 请求体并将其传递给下一个处理程序的中间件函数。
///
/// 使用 `req_decrypt` 解密请求体，验证和处理加密数据，并将解密后的请求传递给下一个中间件或处理程序。如果解密或验证失败，
/// 则返回适当的错误响应。
///
/// # 参数
///
/// - `req`: 要解密的 HTTP 请求。
/// - `next`: 链中的下一个中间件或处理程序。
///
/// # 返回值
///
/// 返回一个 `Result`，包含 `axum::http::Response` 如果解密和处理成功，或者包含 `DecryptExtError` 如果解密或验证过程中出现错误。
///
/// # 错误
///
/// 返回以下几种错误类型：
/// - `DecryptExtError::DecryptError`: 一般解密错误。
/// - `DecryptExtError::JsonError`: JSON 解析或序列化错误。
/// - `DecryptExtError::VerificationError`: 数据验证错误。
///
/// # 示例
///
/// ```
/// use axum::{body::Body, response::Response, Router};
/// use my_middleware::{mw_req_decrypt_resolver, DecryptExtError};
///
/// async fn handler() -> &'static str {
///     "Hello, world!"
/// }
///
/// let app = Router::new()
///     .route("/api", axum::post(handler).layer(mw_req_decrypt_resolver));
/// ```
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

/// 解密 HTTP 请求体并验证加密数据的异步函数。
///
/// 解密请求体，验证和处理加密数据。如果解密和处理成功，则返回解密后的字节流；如果解密或验证过程中出现错误，则返回 `DecryptExtError`。
///
/// # 参数
///
/// - `body`: 要解密的 HTTP 请求体，实现了 `axum::body::HttpBody<Data = Bytes>`。
///
/// # 返回值
///
/// 返回一个 `Result`，包含 `Bytes` 如果解密和处理成功，或者包含 `DecryptExtError` 如果解密或验证过程中出现错误。
///
/// # 错误
///
/// 返回以下几种错误类型：
/// - `DecryptExtError::DecryptError`: 一般解密错误。
/// - `DecryptExtError::JsonError`: JSON 解析或序列化错误。
/// - `DecryptExtError::VerificationError`: 数据验证错误。
///
/// # 示例
///
/// ```
/// use axum::{body::Body, response::Response};
/// use my_middleware::{req_decrypt, DecryptExtError};
/// use axum::body::Bytes;
///
/// async fn handler(body: Body) -> Result<Response<Body>, axum::Error> {
///     let bytes = req_decrypt(body).await?;
///     Ok(Response::new(bytes.into()))
/// }
/// ```
async fn req_decrypt<B>(body: B) -> BytesExtResult
where
    B: axum::body::HttpBody<Data = Bytes>,
    B::Error: std::fmt::Display,
{
    let bytes = body
        .collect()
        .await
        .map_err(|_| DecryptExtError::DecryptError)?
        .to_bytes();

    let body_str = std::str::from_utf8(&bytes).map_err(|_| DecryptExtError::DecryptError)?;

    let encrypted_data = model::EncryptedData::from_json(body_str)
        .map_err(|_| DecryptExtError::JsonError)?;

    let verify_and_decrypt = encrypted_data
        .verify_and_decrypt()
        .map_err(|_| DecryptExtError::VerificationError)?;

    Ok(verify_and_decrypt.into())
}
type BytesExtResult = core::result::Result<Bytes, DecryptExtError>;

/// 自定义错误枚举，用于表示解密和处理过程中可能出现的错误。
#[derive(Clone, Serialize, Debug)]
pub enum DecryptExtError {
    DecryptError,       // 一般解密错误
    JsonError,          // JSON 解析或序列化错误
    VerificationError,  // 数据验证错误
}
