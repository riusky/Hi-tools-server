use crate::ctx::Ctx;
use crate::generate_common_bmc_fns;
use crate::model::base::{self, DbBmc};
use crate::model::conv_msg::{
	ConvMsg, ConvMsgBmc, ConvMsgForCreate, ConvMsgForInsert,
};
use crate::model::modql_utils::time_to_sea_value;
use crate::model::ModelManager;
use crate::model::Result;
use lib_utils::time::Rfc3339;
use modql::field::{Fields, SeaFieldValue};
use modql::filter::{
	FilterNodes, ListOptions, OpValsInt64, OpValsString, OpValsValue,
};
use sea_query::Nullable;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sqlx::types::time::OffsetDateTime;
use sqlx::FromRow;

// region:    --- 会话类型

/// 实现此特性的实体具有 conv_id 方法
/// 这将允许将 Ctx 升级为具有相应 conv_id 的状态，以便将来进行访问控制。
pub trait ConvScoped {
	fn conv_id(&self) -> i64;
}

#[derive(Debug, Clone, sqlx::Type, derive_more::Display, Deserialize, Serialize)]
#[sqlx(type_name = "conv_kind")]
#[cfg_attr(test, derive(PartialEq))]
pub enum ConvKind {
	OwnerOnly,
	MultiUsers,
}

/// 注意：手动实现
///       必须为 modql::field::Fields 提供实现
impl From<ConvKind> for sea_query::Value {
	fn from(val: ConvKind) -> Self {
		val.to_string().into()
	}
}

/// 注意：手动实现
///       在 None 情况下，sea::query 需要此实现。
///       但是，在此代码库中，我们使用 modql 的 not_none_field，
///       所以这个实现将被忽略。
///       尽管如此，它仍然是编译所必需的。
impl Nullable for ConvKind {
	fn null() -> sea_query::Value {
		ConvKind::OwnerOnly.into()
	}
}

/// 注意：这里我们从 modql 的 `SeaFieldValue` 派生，它实现了
///       `From<ConvState> for sea_query::Value` 和
///       `sea_query::value::Nullable for ConvState`
///       请参见 `ConvKind` 的手动实现。
#[derive(
	Debug,
	Clone,
	sqlx::Type,
	SeaFieldValue,
	derive_more::Display,
	Deserialize,
	Serialize,
)]
#[sqlx(type_name = "conv_state")]
pub enum ConvState {
	Active,
	Archived,
}

#[serde_as]
#[derive(Debug, Clone, Fields, FromRow, Serialize)]
pub struct Conv {
	pub id: i64,

	// -- 关系
	pub agent_id: i64,
	pub owner_id: i64,

	// -- 属性
	pub title: Option<String>,
	pub kind: ConvKind,
	pub state: ConvState,

	// -- 时间戳
	// 创建者用户 ID 和时间
	pub cid: i64,
	#[serde_as(as = "Rfc3339")]
	pub ctime: OffsetDateTime,
	// 最后修改者用户 ID 和时间
	pub mid: i64,
	#[serde_as(as = "Rfc3339")]
	pub mtime: OffsetDateTime,
}

#[derive(Fields, Deserialize, Default)]
pub struct ConvForCreate {
	pub agent_id: i64,

	pub title: Option<String>,

	#[field(cast_as = "conv_kind")]
	pub kind: Option<ConvKind>,
}

#[derive(Fields, Deserialize, Default)]
pub struct ConvForUpdate {
	pub owner_id: Option<i64>,
	pub title: Option<String>,
	pub closed: Option<bool>,
	#[field(cast_as = "conv_state")]
	pub state: Option<ConvState>,
}

#[derive(FilterNodes, Deserialize, Default, Debug)]
pub struct ConvFilter {
	pub id: Option<OpValsInt64>,

	pub owner_id: Option<OpValsInt64>,
	pub agent_id: Option<OpValsInt64>,

	#[modql(cast_as = "conv_kind")]
	pub kind: Option<OpValsString>,

	pub title: Option<OpValsString>,

	pub cid: Option<OpValsInt64>,
	#[modql(to_sea_value_fn = "time_to_sea_value")]
	pub ctime: Option<OpValsValue>,
	pub mid: Option<OpValsInt64>,
	#[modql(to_sea_value_fn = "time_to_sea_value")]
	pub mtime: Option<OpValsValue>,
}

// endregion: --- 会话类型

// region:    --- 会话 BMC

pub struct ConvBmc;

impl DbBmc for ConvBmc {
	const TABLE: &'static str = "conv";

	fn has_owner_id() -> bool {
		true
	}
}

// 这将生成带有默认 CRUD 函数的 `impl ConvBmc {...}`。
generate_common_bmc_fns!(
	Bmc: ConvBmc,
	Entity: Conv,
	ForCreate: ConvForCreate,
	ForUpdate: ConvForUpdate,
	Filter: ConvFilter,
);

// 其他用于管理 `ConvMsg` 构造的 ConvBmc 方法。
impl ConvBmc {
	/// 向会话添加 `ConvMsg`
	///
	/// 为了进行访问控制，我们将添加：
	/// #[ctx_add(conv, space)]
	/// #[requires_privilege_any_of("og:FullAccess", "sp:FullAccess", "conv@owner_id" "conv:AddMsg")]
	pub async fn add_msg(
		ctx: &Ctx,
		mm: &ModelManager,
		msg_c: ConvMsgForCreate,
	) -> Result<i64> {
		let msg_i = ConvMsgForInsert::from_msg_for_create(ctx.user_id(), msg_c);
		let conv_msg_id = base::create::<ConvMsgBmc, _>(ctx, mm, msg_i).await?;

		Ok(conv_msg_id)
	}

	/// 注意：当前策略是不需要 conv_id，但我们将检查
	///       用户是否在相应的会话中拥有 `conv:ReadMsg` 特权（在 base::get 之后）。
	pub async fn get_msg(
		ctx: &Ctx,
		mm: &ModelManager,
		msg_id: i64,
	) -> Result<ConvMsg> {
		let conv_msg: ConvMsg = base::get::<ConvMsgBmc, _>(ctx, mm, msg_id).await?;

		// TODO: 验证 conv_msg 是否属于 ctx.conv_id
		//       let _ctx = ctx.add_conv_id(conv_msg.conv_id());
		//       assert_privileges(&ctx, &mm, &["conv@owner_id", "conv:ReadMsg"]);

		Ok(conv_msg)
	}
}

// endregion: --- 会话 BMC

// region:    --- 测试

#[cfg(test)]
mod tests {
	type Error = Box<dyn std::error::Error>;
	type Result<T> = core::result::Result<T, Error>; // 用于测试。

	use super::*;
	use crate::_dev_utils::{self, seed_agent};
	use crate::ctx::Ctx;
	use crate::model::agent::AgentBmc;
	use modql::filter::OpValString;
	use serial_test::serial;

	#[serial]
	#[tokio::test]
	async fn test_create_ok() -> Result<()> {
		// -- 设置和初始化数据
		let mm = _dev_utils::init_test().await;
		let ctx = Ctx::root_ctx();
		let fx_title = "test_create_ok conv 01";
		let fx_kind = ConvKind::MultiUsers;
		let agent_id = seed_agent(&ctx, &mm, "test_create_ok conv agent 01").await?;

		// -- 执行
		let conv_id = ConvBmc::create(
			&ctx,
			&mm,
			ConvForCreate {
				agent_id,
				title: Some(fx_title.to_string()),
				kind: Some(fx_kind.clone()),
			},
		)
		.await?;

		// -- 检查
		let conv: Conv = ConvBmc::get(&ctx, &mm, conv_id).await?;
		assert_eq!(&conv.kind, &fx_kind);
		assert_eq!(conv.title.ok_or("conv should have title")?, fx_title);

		// -- 清理
		ConvBmc::delete(&ctx, &mm, conv_id).await?;
		AgentBmc::delete(&ctx, &mm, agent_id).await?;

		Ok(())
	}

	#[serial]
	#[tokio::test]
	async fn test_list_ok() -> Result<()> {
		// -- 设置和初始化数据
		let mm = _dev_utils::init_test().await;
		let ctx = Ctx::root_ctx();
		let fx_title_prefix = "test_list_ok conv - ";
		let agent_id = seed_agent(&ctx, &mm, "test_create_ok conv agent 01").await?;

		for i in 1..=6 {
			let kind = if i <= 3 {
				ConvKind::OwnerOnly
			} else {
				ConvKind::MultiUsers
			};

			let _conv_id = ConvBmc::create(
				&ctx,
				&mm,
				ConvForCreate {
					agent_id,
					title: Some(format!("{fx_title_prefix}{:<02}", i)),
					kind: Some(kind),
				},
			)
			.await?;
		}

		// -- 执行
		let convs = ConvBmc::list(
			&ctx,
			&mm,
			Some(vec![ConvFilter {
				agent_id: Some(agent_id.into()),

				kind: Some(OpValString::In(vec!["MultiUsers".to_string()]).into()),
				// 或者
				// kind: Some(OpValString::Eq("MultiUsers".to_string()).into()),
				..Default::default()
			}]),
			None,
		)
		.await?;

		// -- 检查
		// 提取标题中的 04、05、06 部分
		let num_parts = convs
			.iter()
			.filter_map(|c| c.title.as_ref().and_then(|s| s.split("- ").nth(1)))
			.collect::<Vec<&str>>();
		assert_eq!(num_parts, &["04", "05", "06"]);

		// -- 清理
		// 这应该级联删除
		AgentBmc::delete(&ctx, &mm, agent_id).await?;

		Ok(())
	}
}

// endregion: --- 测试
