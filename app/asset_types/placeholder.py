from app.asset_types.base import AssetType, obj
from app.core.security import GatewayError


class PlaceholderAssetType(AssetType):
    """插件缺失或未启用时的占位类型。

    保留 asset_types 表中的元数据与 Schema 快照，控制台可以回显既有资产的表单，
    但禁止新建资产、编辑账号与执行工具；插件启用时由注册表替换本占位。
    """

    placeholder = True
    available = False

    def __init__(self, type_id, display_name="", schemas=None, plugin_id=None):
        self.type_id = type_id
        self.display_name = display_name or type_id
        self.plugin_id = plugin_id
        schemas = schemas or {}
        self.connection_schema = schemas.get("connection_schema") or obj({})
        self.account_schema = schemas.get("account_schema") or obj({})
        self.credential_schema = schemas.get("credential_schema") or obj({})
        self.policy_schema = schemas.get("policy_schema") or obj({})

    def description(self):
        value = super().description()
        value["plugin_missing"] = True
        if self.plugin_id:
            value["plugin"] = {"id": self.plugin_id}
        return value

    def _reject(self):
        raise GatewayError(
            "PLUGIN_MISSING", f"插件缺失或未启用：资产类型 {self.type_id} 暂不可用，请先在插件中心处理", 503
        )

    def validate_connection(self, network, connection):
        self._reject()

    def catalog(self, account):
        return []

    def validate_config(self, connection, account, policy, credential):
        self._reject()
