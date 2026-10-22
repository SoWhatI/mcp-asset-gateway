import threading

from app.core.security import GatewayError


class TypeRegistry:
    """资产类型注册表：内置类型与插件类型统一入口。

    entries()/prepare() 在数据库线程池中并发读取，启停插件又在事件循环里改写，
    因此所有访问都持锁；返回列表的接口一律给拷贝，调用方不持锁遍历。
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._kinds = {}
        self._sources = {}

    def register(self, kind, plugin_id=None, version_id=None, artifact_hash=None, replace_placeholder=False):
        """注册资产类型；replace_placeholder 用于插件启用时替换占位类型。"""
        with self._lock:
            existing = self._kinds.get(kind.type_id)
            if existing is not None and not (replace_placeholder and getattr(existing, "placeholder", False)):
                raise GatewayError("TYPE_CONFLICT", f"资产类型 {kind.type_id} 已被占用", 409)
            self._kinds[kind.type_id] = kind
            self._sources[kind.type_id] = (
                {"plugin_id": plugin_id, "version_id": version_id, "artifact_hash": artifact_hash}
                if plugin_id
                else None
            )

    def unregister(self, type_id):
        with self._lock:
            self._kinds.pop(type_id, None)
            self._sources.pop(type_id, None)

    def source(self, type_id):
        """类型来源信息；内置类型返回 None，插件类型返回插件版本描述。"""
        with self._lock:
            return dict(self._sources[type_id]) if self._sources.get(type_id) else None

    def artifact_hash(self, type_id):
        return (self.source(type_id) or {}).get("artifact_hash")

    def proxied_ids(self):
        """动态目录型类型列表，供 ensure_catalogs 的 SQL IN 条件使用。"""
        with self._lock:
            return sorted(key for key, kind in self._kinds.items() if kind.proxied)

    def get(self, type_id):
        with self._lock:
            return self._kinds.get(type_id)

    def values(self):
        with self._lock:
            return list(self._kinds.values())

    def items(self):
        with self._lock:
            return list(self._kinds.items())

    def __contains__(self, type_id):
        with self._lock:
            return type_id in self._kinds

    def __iter__(self):
        with self._lock:
            return iter(list(self._kinds))

    def __len__(self):
        with self._lock:
            return len(self._kinds)

    def __getitem__(self, type_id):
        with self._lock:
            if type_id not in self._kinds:
                raise GatewayError("ASSET_TYPE", "资产类型不存在或未注册", 400)
            return self._kinds[type_id]
