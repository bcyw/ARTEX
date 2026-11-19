import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "不吃鱼尾的工作台",
  version: packageJson.version,
  copyright: `© ${currentYear}, 不吃鱼尾的工作台.`,
  meta: {
    title: "不吃鱼尾的工作台 — 自主渗透测试控制台",
    description: "LLM 驱动的自主渗透测试系统控制台",
  },
};
