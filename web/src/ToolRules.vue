<script setup>
import { computed, ref } from "vue";

const props = defineProps({ modelValue: { type: Object, default: () => ({}) }, schema: Object });
const emit = defineEmits(["update:modelValue"]);
const pending = ref("");
const properties = computed(() => props.schema?.properties || {});
const available = computed(() => Object.keys(properties.value).filter((key) => !Object.hasOwn(props.modelValue, key)));
const lists = [{ key: "allow", label: "白名单" }, { key: "deny", label: "黑名单" }];
function update(fn) {
  const value = JSON.parse(JSON.stringify(props.modelValue));
  fn(value);
  emit("update:modelValue", value);
}
function addParameter() {
  if (!pending.value) return;
  emit("update:modelValue", { ...props.modelValue, [pending.value]: {} });
  pending.value = "";
}
function addRule(parameter, list) {
  update((value) => {
    value[parameter][list] ||= [];
    value[parameter][list].push({ match: "exact", value: "" });
  });
}
function changeRule(parameter, list, index, key, content) {
  update((value) => { value[parameter][list][index][key] = content; });
}
</script>

<template>
  <el-collapse class="parameter-rules">
    <el-collapse-item :title="`参数黑白名单（${Object.keys(modelValue).length} 个参数）`" name="rules">
      <p class="rules-help">未配置规则时不额外限制。黑名单优先；同参数多条规则满足任一条，组内多个参数白名单必须同时满足。跨组白名单取并集，但任一适用组的黑名单均可拒绝调用。</p>
      <p class="rules-help">精确匹配和正则均匹配全文，保留首尾空白。字符串直接填写；数组、对象等填写紧凑 JSON（对象键排序），例如 ["uname","-a"]。规则仅约束顶层参数，不是 shell 沙箱。</p>
      <div v-for="(rules, parameter) in modelValue" :key="parameter" class="parameter-rule">
        <div class="parameter-title">
          <strong>{{ parameter }} · {{ properties[parameter]?.title || properties[parameter]?.type || '参数已不在目录中，请移除' }}</strong>
          <el-button link type="danger" @click="update((value) => { delete value[parameter]; })">移除参数</el-button>
        </div>
        <div v-for="list in lists" :key="list.key" class="rule-list">
          <div class="parameter-title">
            <span>{{ list.label }}</span>
            <el-button size="small" :disabled="(rules[list.key]?.length || 0) >= 50" @click="addRule(parameter, list.key)">添加{{ list.label }}</el-button>
          </div>
          <div v-for="(rule, index) in rules[list.key] || []" :key="index" class="rule-row">
            <el-select :model-value="rule.match" :aria-label="`${parameter} ${list.label}匹配方式 ${index + 1}`" @update:model-value="changeRule(parameter, list.key, index, 'match', $event)">
              <el-option label="精确匹配" value="exact" />
              <el-option label="正则表达式" value="regex" />
            </el-select>
            <el-input type="textarea" :autosize="{ minRows: 1, maxRows: 4 }" :maxlength="4096" :model-value="rule.value" :aria-label="`${parameter} ${list.label}规则 ${index + 1}`" :placeholder="rule.match === 'regex' ? '全文匹配，例如 uname( -a)?' : '精确文本（可为空串）'" @update:model-value="changeRule(parameter, list.key, index, 'value', $event)" />
            <el-button link type="danger" :aria-label="`删除 ${parameter} ${list.label}规则 ${index + 1}`" @click="update((value) => value[parameter][list.key].splice(index, 1))">删除</el-button>
          </div>
          <small v-if="!rules[list.key]?.length" class="rules-help">未配置{{ list.label }}，不增加此类限制</small>
        </div>
      </div>
      <div class="parameter-add">
        <el-select v-model="pending" filterable placeholder="选择需要限制的参数" aria-label="选择需要限制的参数">
          <el-option v-for="key in available" :key="key" :value="key" :label="`${key} · ${properties[key].title || properties[key].type || ''}`" />
        </el-select>
        <el-button :disabled="!pending || Object.keys(modelValue).length >= 32" @click="addParameter">添加参数规则</el-button>
      </div>
      <small class="rules-help">正则由服务端校验并限时匹配。省略受约束参数时使用 schema 默认值；无默认值时黑名单要求显式传参，白名单视为不匹配。点击完成后仍需保存授权组。</small>
    </el-collapse-item>
  </el-collapse>
</template>

<style scoped>
.parameter-rules { margin-top: 8px; }
.rules-help { color: #85899b; font-size: 12px; line-height: 1.7; white-space: normal; }
.parameter-rule { padding: 12px; margin: 12px 0; border: 1px solid #e8eaf1; border-radius: 6px; }
.parameter-title, .parameter-add { display: flex; gap: 12px; align-items: center; justify-content: space-between; }
.parameter-title strong { overflow-wrap: anywhere; }
.rule-list { margin-top: 10px; }
.rule-row { display: grid; grid-template-columns: 130px minmax(0, 1fr) 36px; gap: 8px; align-items: start; margin: 8px 0; }
.parameter-add { margin: 12px 0; }
@media (max-width: 600px) {
  .rule-row { grid-template-columns: minmax(0, 1fr) 36px; }
  .rule-row .el-select { grid-column: 1 / -1; }
}
</style>
