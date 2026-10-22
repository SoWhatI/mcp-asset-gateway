<script setup>
import { computed, onMounted, onUnmounted, reactive, ref } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import { api } from "./api";

const tab = ref("market");
const busy = ref(false);
const marketQuery = ref("");
const marketItems = ref([]);
const marketError = ref("");
const installed = ref([]);
const jobs = ref([]);
const runtimePlugin = ref("");
const runtime = ref(null);
let pollTimer = null;

const marketFiltered = computed(() => marketItems.value);

async function run(task) {
  busy.value = true;
  try {
    return await task();
  } catch (error) {
    ElMessage.error(String(error.message || error));
    return null;
  } finally {
    busy.value = false;
  }
}

async function refreshMarket() {
  await run(async () => {
    try {
      const suffix = marketQuery.value.trim() ? `?query=${encodeURIComponent(marketQuery.value.trim())}` : "";
      const data = await api(`/plugins/market${suffix}`);
      marketItems.value = data.items || [];
      marketError.value = "";
    } catch (error) {
      marketItems.value = [];
      marketError.value = String(error.message || error);
    }
  });
}

async function refreshInstalled() {
  await run(async () => {
    const data = await api("/plugins");
    installed.value = data.items || [];
  });
}

async function refreshJobs() {
  const data = await api("/plugins/jobs");
  jobs.value = data.items || [];
  schedulePoll();
}

function schedulePoll() {
  clearTimeout(pollTimer);
  if (tab.value === "jobs" && jobs.value.some((job) => job.status === "pending" || job.status === "running"))
    pollTimer = setTimeout(refreshJobs, 2000);
  if (tab.value === "market" && jobs.value.some((job) => job.status === "pending" || job.status === "running"))
    pollTimer = setTimeout(refreshJobs, 2000);
}

async function switchTab(name) {
  if (name === "market") await refreshMarket();
  if (name === "installed") await refreshInstalled();
  if (name === "jobs") await refreshJobs();
  if (name === "runtime" && runtimePlugin.value) await refreshRuntime();
}

async function confirmInstall(plugin, version) {
  await ElMessageBox.confirm(
    `将安装 ${plugin.id} ${version.version}。发布者：${plugin.publisher}。` +
      `能力声明：网络访问 ${plugin.capabilities?.network ? "是" : "否"}、凭据 ${plugin.capabilities?.credential ? "是" : "否"}、写操作 ${plugin.capabilities?.write ? "是" : "否"}。` +
      `制品哈希 ${String(version.sha256 || "").slice(0, 16)}…。安装后需手动启用。`,
    "确认安装插件",
    { type: "warning", confirmButtonText: "确认安装" },
  ).catch(() => Promise.reject(new Error("cancelled")));
}

async function install(plugin, version) {
  try {
    await confirmInstall(plugin, version);
  } catch {
    return;
  }
  await run(async () => {
    await api("/plugins/install", {
      method: "POST",
      body: { plugin_id: plugin.id, version: version.version, confirm_hash: version.sha256 },
    });
    ElMessage.success("安装任务已创建，请在安装任务页查看进度");
    await refreshJobs();
  });
}

async function upgrade(pluginId, version, sha256) {
  await ElMessageBox.confirm(
    `升级到 ${version}？已有账号配置会先校验兼容性；插件代码变化后相关工具授权需要重新确认。`,
    "确认升级",
    { type: "warning" },
  );
  await run(async () => {
    await api(`/plugins/${pluginId}/upgrade`, {
      method: "POST",
      body: { version, confirm_hash: sha256 },
    });
    ElMessage.success("升级任务已创建");
    await refreshJobs();
    await refreshInstalled();
  });
}

async function rollback(pluginId, version) {
  await ElMessageBox.confirm(
    `回滚到 ${version}？回滚后相关工具授权需要重新确认，不会自动恢复历史授权。`,
    "确认回滚",
    { type: "warning" },
  );
  await run(async () => {
    await api(`/plugins/${pluginId}/rollback`, { method: "POST", body: { version } });
    ElMessage.success("已回滚");
    await refreshInstalled();
  });
}

async function enable(plugin) {
  await run(async () => {
    await api(`/plugins/${plugin.id}/enable`, { method: "POST" });
    ElMessage.success("插件已启用，新资产类型立即可用");
    await refreshInstalled();
  });
}

async function disable(plugin) {
  await ElMessageBox.confirm(
    "停用后该插件的工具立即停止放行，在途调用最多等待 30 秒；资产、凭据与授权记录保留。",
    "确认停用",
    { type: "warning" },
  );
  await run(async () => {
    await api(`/plugins/${plugin.id}/disable`, { method: "POST" });
    ElMessage.success("插件已停用");
    await refreshInstalled();
  });
}

async function uninstall(plugin) {
  await ElMessageBox.confirm(
    "卸载会删除插件文件与版本记录；存在关联资产时会拒绝，请先处理关联资产。",
    "确认卸载",
    { type: "warning" },
  );
  await run(async () => {
    await api(`/plugins/${plugin.id}/uninstall`, { method: "POST" });
    ElMessage.success("插件已卸载");
    await refreshInstalled();
  });
}

async function refreshRuntime() {
  if (!runtimePlugin.value) {
    runtime.value = null;
    return;
  }
  await run(async () => {
    runtime.value = await api(`/plugins/${runtimePlugin.value}/runtime`);
  });
}

function retry(job) {
  const target = marketItems.value.find((item) => item.id === job.plugin_id);
  const version = target?.versions.find((entry) => entry.version === job.version);
  if (target && version) return install(target, version);
  ElMessage.info("请先刷新市场后再重试");
}

function jobStatusText(status) {
  return { pending: "等待中", running: "执行中", done: "已完成", failed: "失败" }[status] || status;
}

function versionInstalled(id, version) {
  return installed.value.find((item) => item.id === id)?.versions.some((entry) => entry.version === version);
}

const mounted = reactive({ loaded: false });
onMounted(async () => {
  await refreshInstalled();
  await refreshJobs();
  await refreshMarket();
  mounted.loaded = true;
});
onUnmounted(() => clearTimeout(pollTimer));
</script>

<template>
  <div class="plugin-center">
    <el-tabs v-model="tab" @tab-change="switchTab">
      <el-tab-pane label="插件市场" name="market">
        <div class="plugin-toolbar">
          <el-input
            v-model="marketQuery"
            placeholder="按名称、发布者或描述搜索"
            clearable
            style="max-width: 320px"
            @change="refreshMarket"
          >
          </el-input>
          <el-button @click="refreshMarket">刷新市场</el-button>
        </div>
        <el-alert
          v-if="marketError"
          type="warning"
          :title="marketError"
          description="插件市场不可达不影响已启用插件与网关运行；请检查 PLUGIN_MARKET_URL 与 PLUGIN_MARKET_PUBLIC_KEY 配置。"
          :closable="false"
          show-icon
        />
        <div v-else class="plugin-grid">
          <div v-for="item in marketFiltered" :key="item.id" class="panel plugin-card">
            <div class="plugin-card-head">
              <strong>{{ item.name }}</strong>
              <span class="plugin-publisher">{{ item.publisher }}</span>
            </div>
            <p class="plugin-desc">{{ item.description }}</p>
            <div class="plugin-tags">
              <el-tag v-if="item.capabilities?.network" size="small" type="warning">网络访问</el-tag>
              <el-tag v-if="item.capabilities?.credential" size="small" type="danger">使用凭据</el-tag>
              <el-tag v-if="item.capabilities?.write" size="small" type="danger">写操作</el-tag>
            </div>
            <div v-for="version in item.versions" :key="version.version" class="plugin-version-row">
              <div class="plugin-version-meta">
                <strong>{{ version.version }}</strong>
                <span v-if="version.version === item.latest_version" class="muted">最新</span>
                <el-tooltip v-if="version.changes" :content="version.changes">
                  <span class="muted">更新说明</span>
                </el-tooltip>
              </div>
              <el-button
                size="small"
                type="primary"
                :disabled="busy"
                @click="install(item, version)"
              >
                {{ versionInstalled(item.id, version.version) ? "重装" : "安装" }}
              </el-button>
            </div>
          </div>
          <p v-if="!marketFiltered.length && mounted.loaded" class="muted">市场暂无插件。</p>
        </div>
      </el-tab-pane>

      <el-tab-pane label="已安装" name="installed">
        <el-table :data="installed" empty-text="尚未安装插件">
          <el-table-column prop="id" label="插件" min-width="180" />
          <el-table-column prop="current_version" label="当前版本" width="100" />
          <el-table-column label="状态" width="140">
            <template #default="{ row }">
              <el-tag v-if="row.running" type="success" size="small">运行中</el-tag>
              <el-tag v-else-if="row.expected_state === 'enabled' && !row.files_present" type="danger" size="small">
                插件缺失
              </el-tag>
              <el-tag v-else-if="row.expected_state === 'enabled'" type="warning" size="small">启用异常</el-tag>
              <el-tag v-else type="info" size="small">已停用</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="asset_count" label="关联资产" width="90" />
          <el-table-column label="制品哈希" min-width="150">
            <template #default="{ row }">
              <span class="mono">{{ String(row.artifact_hash || "").slice(0, 16) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="230" fixed="right">
            <template #default="{ row }">
              <el-button
                v-if="row.expected_state !== 'enabled'"
                link
                type="primary"
                :disabled="busy || !row.files_present"
                @click="enable(row)"
                >启用</el-button
              >
              <el-button v-else link type="warning" :disabled="busy" @click="disable(row)">停用</el-button>
              <el-button
                v-for="entry in row.versions.filter((v) => v.version !== row.current_version)"
                :key="'rb-' + entry.version"
                link
                type="info"
                :disabled="busy || !entry.files_present"
                @click="rollback(row.id, entry.version)"
                >回滚 {{ entry.version }}</el-button
              >
              <el-button link type="danger" :disabled="busy" @click="uninstall(row)">卸载</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="安装任务" name="jobs">
        <el-table :data="jobs" empty-text="暂无安装任务">
          <el-table-column prop="plugin_id" label="插件" min-width="160" />
          <el-table-column prop="version" label="版本" width="90" />
          <el-table-column label="动作" width="80">
            <template #default="{ row }">
              {{ { install: "安装", upgrade: "升级", rollback: "回滚", uninstall: "卸载", enable: "启用", disable: "停用" }[row.action] || row.action }}
            </template>
          </el-table-column>
          <el-table-column label="状态" width="180">
            <template #default="{ row }">
              <span>{{ jobStatusText(row.status) }}</span>
              <el-progress
                v-if="row.status === 'running'"
                :percentage="row.progress"
                :stroke-width="6"
                style="margin-top: 4px"
              />
            </template>
          </el-table-column>
          <el-table-column label="错误" min-width="220">
            <template #default="{ row }">
              <span v-if="row.error" class="plugin-error">{{ row.error.code }}：{{ row.error.message }}</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="80">
            <template #default="{ row }">
              <el-button v-if="row.status === 'failed'" link type="primary" @click="retry(row)">重试</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="运行状态" name="runtime">
        <div class="plugin-toolbar">
          <el-select v-model="runtimePlugin" placeholder="选择已启用插件" style="max-width: 320px" @change="refreshRuntime">
            <el-option
              v-for="item in installed.filter((row) => row.running)"
              :key="item.id"
              :label="item.id"
              :value="item.id"
            />
          </el-select>
          <el-button :disabled="!runtimePlugin" @click="refreshRuntime">刷新</el-button>
        </div>
        <template v-if="runtime?.pool">
          <p>
            工作进程：{{ runtime.pool.workers.filter((w) => w.alive).length }}/{{ runtime.pool.max_workers }} 可用
          </p>
          <ul class="plugin-stats">
            <li>累计调用：{{ runtime.pool.stats.requests }}</li>
            <li>错误：{{ runtime.pool.stats.errors }}（超时 {{ runtime.pool.stats.timeouts }}、进程异常 {{ runtime.pool.stats.crashes }}）</li>
            <li>进程启动次数：{{ runtime.pool.stats.spawns }}</li>
          </ul>
          <div v-if="runtime.pool.recent_errors.length" class="plugin-recent">
            <div v-for="(error, index) in runtime.pool.recent_errors.slice(-8)" :key="index" class="plugin-error-row">
              {{ new Date(error.ts).toLocaleString() }} {{ error.code }}：{{ error.message }}
            </div>
          </div>
        </template>
        <p v-else-if="runtimePlugin" class="muted">该插件当前没有运行中的进程池。</p>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>
