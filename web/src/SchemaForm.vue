<script setup>
import { computed, reactive } from "vue";
import { ElMessage } from "element-plus";
import { Upload } from "@element-plus/icons-vue";
const props = defineProps({ schema: Object, modelValue: Object });
const emit = defineEmits(["update:modelValue"]);
const loaded = reactive({});
// 多行数组字段以草稿编辑：回车换行不立即回写，失焦时逐行去空后提交。
const drafts = reactive({});
function commitDraft(key) {
  if (drafts[key] === undefined) return;
  const value = drafts[key]
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
  delete drafts[key];
  set(key, value.length ? value : undefined);
}
const visibleFields = computed(() =>
  Object.fromEntries(
    Object.entries(props.schema?.properties || {}).filter(
      ([, field]) => !field["x-hidden"],
    ),
  ),
);
function set(key, value) {
  const next = { ...props.modelValue };
  if (value === "" || value === undefined || value === null) delete next[key];
  else next[key] = value;
  emit("update:modelValue", next);
}
// 手工输入视为放弃此前上传的文件，避免提示与实际内容不一致。
function setFromInput(key, value) {
  if (loaded[key]) delete loaded[key];
  set(key, value);
}
// 失焦时清理首尾空白（粘贴常见）；凭据字段保持原样，不做任何改动。
function normalize(key, event) {
  const field = props.schema?.properties?.[key] || {};
  if (field.format === "password" || key === "private_key" || key === "sql")
    return;
  const value = String(event.target.value ?? "");
  if (value !== value.trim()) set(key, value.trim());
}
// 读取上传文件内容直接作为字段值；凭据字段随凭据加密保存，其余字段随对象保存。
async function loadFile(key, upload) {
  const file = upload?.raw;
  if (!file) return;
  if (file.size > 256 * 1024) {
    ElMessage.warning("文件超过 256 KB，请确认为 PEM/证书文件");
    return;
  }
  const content = await file.text();
  if (!content.trim()) {
    ElMessage.warning("文件内容为空，未载入");
    return;
  }
  const size =
    file.size < 1024 ? `${file.size} B` : `${(file.size / 1024).toFixed(1)} KB`;
  loaded[key] = `${file.name}（${size}）`;
  set(key, content);
}
</script>

<template>
  <div class="schema-form">
    <el-form-item
      v-for="(field, key) in visibleFields"
      :key="key"
      :label="field.title || key"
      :required="schema.required?.includes(key)"
    >
      <el-select
        v-if="field.enum"
        :model-value="modelValue?.[key]"
        @update:model-value="set(key, $event)"
        clearable
      >
        <el-option
          v-for="option in field.enum"
          :key="option"
          :label="option"
          :value="option"
        />
      </el-select>
      <el-input-number
        v-else-if="field.type === 'integer' || field.type === 'number'"
        :model-value="modelValue?.[key]"
        :min="field.minimum"
        :max="field.maximum"
        controls-position="right"
        @update:model-value="set(key, $event)"
      />
      <el-switch
        v-else-if="field.type === 'boolean'"
        :model-value="modelValue?.[key] || false"
        @update:model-value="set(key, $event)"
      />
      <el-input
        v-else-if="field.type === 'array'"
        type="textarea"
        :rows="4"
        :model-value="drafts[key] ?? (modelValue?.[key] || []).join('\n')"
        :placeholder="field.description || '每行一项'"
        @update:model-value="drafts[key] = $event"
        @blur="commitDraft(key)"
      />
      <el-input
        v-else
        :model-value="modelValue?.[key] || ''"
        :type="
          field['x-upload'] || key === 'sql'
            ? 'textarea'
            : field.format === 'password'
              ? 'password'
              : 'text'
        "
        :show-password="field.format === 'password' && key !== 'private_key'"
        :rows="4"
        :maxlength="field.maxLength"
        :placeholder="
          field.description ||
          (schema.required?.includes(key) ? '必填' : '留空使用默认策略')
        "
        autocomplete="off"
        @update:model-value="setFromInput(key, $event)"
        @blur="normalize(key, $event)"
      />
      <div v-if="field['x-upload']" class="upload-row">
        <el-upload
          action="#"
          :auto-upload="false"
          :show-file-list="false"
          :on-change="(file) => loadFile(key, file)"
        >
          <el-button size="small" :icon="Upload">上传文件</el-button>
        </el-upload>
        <small v-if="loaded[key]" class="field-hint"
          >已从 {{ loaded[key] }} 载入，保存后生效</small
        >
      </div>
      <small v-if="field.description" class="field-hint">{{
        field.description
      }}</small>
    </el-form-item>
  </div>
</template>
