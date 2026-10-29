#!/usr/bin/env python3
"""渲染 deploy/*.template：把 variables.env 的变量代入 ${VAR} 占位符。

MGMT_REGEX 若未在 variables.env 中显式给出，则按 /24 网段自动推导
（取前三段 + 转义点）；非 /24 网段请在 variables.env 中显式写 MGMT_REGEX。
用法：python3 deploy/render.py deploy/variables.env deploy/ /tmp/gungk-rendered
只写到目标目录，不改模板本身；真实值绝不回写进仓库。
"""
import os
import re
import sys


def load_env(path):
    env = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def mgmt_regex(nets):
    parts = []
    for net in nets.split(","):
        net = net.strip()
        if not net:
            continue
        ip, _, prefix = net.partition("/")
        octets = ip.split(".")
        if prefix == "24" and len(octets) == 4:
            parts.append(r"\.".join(octets[:3]) + r"\.")
        else:
            parts.append(re.escape(ip))
    return "(" + "|".join(parts) + ")"


def main():
    env_path, src_dir, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    env = load_env(env_path)
    if "MGMT_REGEX" not in env and "MGMT_NETS" in env:
        env["MGMT_REGEX"] = mgmt_regex(env["MGMT_NETS"])
    os.makedirs(out_dir, exist_ok=True)
    for name in os.listdir(src_dir):
        if not name.endswith(".template"):
            continue
        with open(os.path.join(src_dir, name), encoding="utf-8") as fh:
            text = fh.read()
        missing = [v for v in set(re.findall(r"\$\{(\w+)\}", text)) if v not in env]
        if missing:
            print(f"跳过 {name}：variables.env 缺少 {missing}")
            continue
        for k, v in env.items():
            text = text.replace("${" + k + "}", v)
        out = os.path.join(out_dir, name[: -len(".template")])
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"已渲染 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
