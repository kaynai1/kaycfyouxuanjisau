# -*- coding: utf-8 -*-
"""不依赖 fnpack 构建 cfopt.fpk。

飞牛的 .fpk 就是 gzip 压缩的 tar：外层放 app.tgz + cmd/ + config/ +
icons + manifest + wizard/，内层 app.tgz 放 src/ + ui/ + config/。
权限按 fnpack 的产物对齐：目录 0777、文件 0666，属主 root。
"""
import io
import os
import tarfile
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(ROOT, "app")
OUT = os.path.join(ROOT, "cfopt.fpk")
NOW = int(time.time())


def norm(info, mode_dir=False):
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = NOW
    info.mode = 0o777 if mode_dir else 0o666
    info.type = tarfile.DIRTYPE if mode_dir else tarfile.REGTYPE
    return info


def add_dir(tf, name):
    info = norm(tarfile.TarInfo(name), True)
    info.size = 0
    tf.addfile(info)


def add_tree(tf, src, arc):
    """递归加入目录，跳过 __pycache__ 和 .pyc。"""
    add_dir(tf, arc)
    for entry in sorted(os.listdir(src)):
        if entry in ("__pycache__",) or entry.endswith(".pyc"):
            continue
        path = os.path.join(src, entry)
        child = f"{arc}/{entry}"
        if os.path.isdir(path):
            add_tree(tf, path, child)
        else:
            with open(path, "rb") as f:
                data = f.read()
            info = norm(tarfile.TarInfo(child))
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def add_file(tf, path, arc):
    with open(path, "rb") as f:
        data = f.read()
    info = norm(tarfile.TarInfo(arc))
    info.size = len(data)
    tf.addfile(info, io.BytesIO(data))


def build_inner(path):
    with tarfile.open(path, "w:gz") as tf:
        add_tree(tf, os.path.join(APP, "src"), "src")
        add_tree(tf, os.path.join(APP, "ui"), "ui")
        add_tree(tf, os.path.join(ROOT, "config"), "config")


def build_outer(inner_path):
    with tarfile.open(OUT, "w:gz") as tf:
        add_file(tf, inner_path, "app.tgz")
        add_file(tf, os.path.join(ROOT, "ICON.PNG"), "ICON.PNG")
        add_file(tf, os.path.join(ROOT, "ICON_256.PNG"), "ICON_256.PNG")
        add_file(tf, os.path.join(ROOT, "manifest"), "manifest")
        add_tree(tf, os.path.join(ROOT, "cmd"), "cmd")
        add_tree(tf, os.path.join(ROOT, "config"), "config")
        add_dir(tf, "wizard")


if __name__ == "__main__":
    inner = os.path.join(ROOT, "app.tgz")
    build_inner(inner)
    build_outer(inner)
    os.remove(inner)
    print(f"cfopt.fpk = {os.path.getsize(OUT)} 字节")
