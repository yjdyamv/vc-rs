# Mounting non-FAT filesystems — design options

**中文要点 (short version):** Dokany 只能实现“文件系统”，实现不了“裸磁盘”，所以挂载层
必须在用户态自己解析卷内文件系统 —— 这条路最终只实现了 FAT。要让 NTFS / exFAT / ReFS 等
Windows 原生文件系统也能用（包括挂载 VeraCrypt 建的 NTFS 卷），有下面四条路，
我们**采用了 A（iSCSI + Windows 内置发起程序）并已端到端验证**，本文保留当初的选型分析。
A 落地后 Dokany 那条路（方案 C 的 FAT 部分）已从代码里移除，仅保留 `vcrs format`
（在卷内建 FAT 文件系统，不需要挂载）。

| | 方案 | 卷内文件系统 | 额外内核驱动 | 需要管理员 | 需要写的代码 | 风险 |
|---|---|---|---|---|---|---|
| **A** | iSCSI target → Windows 内置发起程序 | **任意**（Windows 自己挂载 NTFS/exFAT/ReFS…） | 无（in-box `msiscsi`） | 是（登录发起程序） | ~600 行（含依赖 `iscsi-target`） | 中：Windows 发起程序互操作性未经该库作者验证 |
| **B** | ImDisk proxy 虚拟盘 | **任意**（ImDisk 转发 I/O，Windows 挂载） | 需装 ImDisk（第三方签名驱动） | 是（装驱动 / 建盘） | ~500 行（devio 管道协议） | 中：依赖老牌第三方驱动，Windows 11 需实测 |
| **C** | 继续用 Dokany，自己实现文件系统 | exFAT（读写）、NTFS（**仅只读**）、ext4（只读/部分写） | 无 | **否** | exFAT ~800 行 / NTFS 只读 ~400 行 | 低（纯用户态），但 NTFS 永远写不了 |
| **D** | 用 Dokany 供一个明文 VHD，让 `vhdmp.sys` 挂载 | 任意 | 无（in-box `vhdmp`） | 是 | ~300 行 | 高：递归 I/O、缓存一致性、性能 |

四条路的共同点是**磁盘上永远只有 VeraCrypt 容器，明文不落盘**：挂载层拿到的都是解密后的扇区。

---

## 现状：为什么 FAT 能挂、NTFS 不能

Dokany 的用户态 API 只有文件系统回调（`CreateFile`/`ReadFile`/`WriteFile`/`FindFiles`…），
没有创建磁盘设备的接口（详见 `docs/research/dokan-mounting.md`）。所以 `vcrs mount`
把「解密后的扇区」交给一个**用户态文件系统**（`crates/vcrs-mount` 里的 `fatfs`），
Windows 只是把我们的回调用成文件系统。要让 NTFS 工作，只有两条路：

1. 自己在用户态实现 NTFS（方案 C，写不动）；
2. 把解密后的卷**变回一块磁盘**交给 Windows，让 Windows 用自带的 NTFS 驱动（方案 A/B/D）。

---

## 方案 A（推荐）：iSCSI target + Windows 内置发起程序

我们的进程做 iSCSI target（TCP 127.0.0.1:3260），Windows 自带的 Microsoft iSCSI
发起程序登录进来，于是卷变成一块**真实的磁盘**：Windows 用自己签名的 NTFS/exFAT 驱动
去读写，用户可以像用 U 盘一样格式化、挂载、分配盘符。

* 协议层已经有现成 crate：`iscsi-target = "1.0.0"`（纯 Rust，MIT/Apache）。
  它实现了 login/logout、discovery（SendTargets）、普通会话、READ/WRITE(6/10/16)、
  INQUIRY + VPD、READ CAPACITY(10/16)、MODE SENSE、REQUEST SENSE、REPORT LUNS、
  TEST UNIT READY、SYNCHRONIZE CACHE、START STOP UNIT、VERIFY，
  支持 immediate data 与多 PDU 写入、可选 CHAP；作者的互操作测试是对着 Linux
  open-iscsi 做的（含 CRC32C digest）。
* 我们只需要实现它的 `ScsiBlockDevice` trait，把 LBA 映射到卷数据区：

  ```rust
  impl ScsiBlockDevice for VolumeScsi {
      fn read(&self, lba: u64, blocks: u32, block_size: u32) -> ScsiResult<Vec<u8>>;  // data_offset + lba*512
      fn write(&mut self, lba: u64, data: &[u8], block_size: u32) -> ScsiResult<()>;
      fn capacity(&self) -> u64;      // data_size / 512
      fn block_size(&self) -> u32;    // 512
      fn flush(&mut self) -> ScsiResult<()>;   // SYNCHRONIZE CACHE -> volume.flush()
  }
  ```

  注意：只暴露**数据区**（LBA 0 = `data_offset`），不暴露头部区——这正是 VeraCrypt
  自己的“文件容器的分区”模型，Windows 看到的是一个已格式化的卷。
* Windows 侧（一次性，需要管理员）：
  `sc start msiscsi` → `iscsicli QAddTargetPortal 127.0.0.1` →
  `iscsicli QLoginTarget iqn.2025-12.vcrs:volume`，之后磁盘出现在磁盘管理器里。
  `vcrs dismount` 时 `iscsicli QLogoutTarget` + 停止 target。
* 命令形式（待实现）：`vcrs mount vol.vc -p pw --raw`（= 走 iSCSI），
  与今天的 `vcrs mount`（= Dokany + FAT）并存。
* 收益：**任意文件系统**，包括 VeraCrypt 建好、已经是 NTFS 的卷（读 + 写），
  以及“Windows 通过它格式化 NTFS 再交回 VeraCrypt 挂载”这条链。
* 风险与对策：
  * Microsoft 发起程序与该 crate 的互操作未经验证 → 先做最小原型（只读挂载一个
    exFAT/NTFS 卷）验证；不通过则回退到自己补齐 PDU 细节（协议不复杂，但工作量上升）。
  * 需要管理员（VeraCrypt 挂载同样需要，用户已接受这个前提）。
  * 性能：本地 TCP 回环 + 单连接，顺序读写足够，随机小块会慢于内核驱动。

## 方案 B（备选）：ImDisk proxy 虚拟盘

ImDisk 的 `proxy` 类型把存储 I/O 通过命名管道转发给一个用户态 storage server
（驱动文档原话：“The actual backingstore for this type of virtual disk is controlled by
an ImDisk storage server accessed by the driver on this machine by sending storage I/O
request through a named pipe specified with `-f`”，参考实现是仓库里的 `devio.c`）。
我们实现管道另一端的服务端，就能得到一块真实卷 —— Windows 自己挂载 NTFS。

* 代码量比 iSCSI 小（单管道二进制协议，没有网络栈和登录协商），
  `imdisk -a -t proxy -f \\.\pipe\vcrs-<n> -s <size> -m Z:` 即可建盘。
* 代价：需要安装 ImDisk（第三方签名驱动，LTRData；驱动较老，
  且 ImDisk “emulates disk volumes rather than complete disks”，对我们反而正好）；
  引入外部依赖与信任面。
* 适合作为 A 的兜底，或作为不希望写网络栈时的选择。

## 方案 C（最省事，但 NTFS 只能读）：继续用 Dokany，自己实现文件系统

* **exFAT**：`exfat-fs` / `exfat` / `embedded-exfat` 等纯 Rust 实现在 crates.io 上已有，
  可以像今天的 FAT 一样接进 Dokany 回调。exFAT 是 Windows 移动盘常用格式，
  且比 NTFS 简单得多；工作量中等。
* **NTFS 只读**：`ntfs = "0.4.0"`（Colin Finck 的 low-level NTFS 库）与
  `ntfs-core = "0.9.8"`（SecurityRonin，MFT/属性/索引/data runs）都是**只读**解析器。
  可以做出 `vcrs mount --fs ntfs --read-only`：无需管理员、无需装驱动，
  就能读取“VeraCrypt 建的 NTFS 卷”里的文件。**写 NTFS 在用户态不现实**。
* ext2/3/4 亦有 Rust 实现，可按同样方式接入（对 Windows 用户价值一般）。
* 优势：保持现在的零依赖挂载与免管理员特性；劣势：每种文件系统都要单独实现，
  且永远覆盖不到 NTFS 写入。

## 方案 D（不建议）：Dokany 供一个明文 VHD，交给 `vhdmp.sys`

用 Dokany 暴露一个“明文 VHD 文件”，Windows 用自带 `vhdmp.sys` 把它当磁盘挂载，
再由 NTFS 驱动挂载里面的文件系统。理论上零新驱动、零第三方依赖，
但 I/O 路径变成 `ntfs.sys → vhdmp.sys → 我们的 Dokany 文件系统 → 解密扇区`，
递归读、缓存一致性、VHD 元数据与锁语义都很容易出问题，性能也差。
只有在 A、B 都走不通时才值得尝试。

---

## 推荐的落地顺序

1. **统一块设备层**（小改动，收益长期）：`crates/vcrs-mount` 里已经有
   `DataArea`/`VolumeDevice`（带 512 字节缓存与写回），让 SCSI 设备、
   将来的 ImDisk 服务端都复用它，保证扇区语义只有一处实现。**已完成。**
2. **方案 A 原型**：`iscsi-target` + `ScsiBlockDevice for Volume`，
   先用只读挂载一个已有的 NTFS/exFAT 卷验证 Windows 发起程序能认；
   通过后补齐 `vcrs mount`、`iscsicli` 登录/登出、`vcrs dismount`。**已完成。**
3. **验证链**（沿用现在的交叉验证套路）：
   * vc-rs 建卷 → `vcrs mount` → Windows `format Z: /FS:NTFS` + 写文件 →
     卸载 → 真实 VeraCrypt 挂载同一容器，读到这些文件；
   * 反向：VeraCrypt（或 Windows）建的 NTFS 容器 → `vcrs mount` → 用资源管理器读写。
   **已完成**（`scripts/vc-iscsi-e2e.ps1`，`RESULT: ALL OK`；反向读写也用同一容器验证过）。
4. **方案 C 的 NTFS 只读**（可选，独立小需求）：给不想装驱动/要管理员的人一条路。
   **未做**，且不建议再投入：Dokany 依赖已移除，且 NTFS 只读对使用价值有限。
5. **方案 B** 作为备选后端：若 A 的 Windows 互操作受阻，就把同一块设备接到
   ImDisk 管道协议上（前端替换，设备层不变）。**未做**（A 已验证可用，无需备选）。

## 参考

* Dokany 能力边界与证据：`docs/research/dokan-mounting.md`
* iSCSI target crate（含 RFC 3720 一致性模型与 Linux 互操作测试）：
  <https://github.com/lawless-m/iscsi-crate>
* ImDisk proxy 说明与 `devio` 参考实现：
  <https://github.com/LTRData/ImDisk>（`devio/devio.c`）
* 只读 NTFS 库：<https://github.com/ColinFinck/ntfs>、
  <https://github.com/SecurityRonin/ntfs-forensic>

## 实施状态（更新）

方案 A **已实现并验证，是唯一的挂载后端**，实现在 `crates/vcrs-mount/src/iscsi.rs`
（CLI：`vcrs mount` / `vcrs dismount --iscsi <iqn>`）。发起程序那一半（把 target 登录进来、
并把磁盘放到指定盘符）在 `crates/vcrs-host/src/attach.rs`：`vcrs mount --letter S` 一条命令
做完“服务 + 挂载”，`vcrs attach` 单独执行挂载那一半（`iscsicli` 带 requireAdministrator
清单，所以这一步必须提权，`vcrs mount --letter` 会自己弹一次 UAC）。提权**十分钟只弹一次**：
第一次提权的那次运行会留下一个 agent（`crates/vcrs-host/src/agent.rs`，一个无窗口的
`vcrs agent --serve`，用命名管道收活），之后十分钟内的 `vcrs mount --letter` /
`vcrs dismount` 都交给它，不再弹 UAC，也不会在卸载过程中闪出提权窗口；
`vcrs agent --status` / `--stop` 可以查看或提前放它走。

挂到指定盘符这一步也不再依赖 PowerShell：Windows 往往在磁盘刚出现时就自己给它一个盘符（
通常是 `D:`），而已经带了盘符的卷拒绝再挂第二个（`SetVolumeMountPointW` 会回
`ERROR_INVALID_PARAMETER`，磁盘就留在 `D:` 上）——所以先把这个自动盘符摘掉，再挂上用户要的
那个；后台服务端的空闲超时也调到 30 秒，足够发起程序在挂载过程中断线重连（原来 5 秒会让服务
在挂载途中自己退出，挂载随后报 “Windows did not show the disk”）。

卸载时也补上了 VeraCrypt 自己那一步：先 `FSCTL_LOCK_VOLUME`（等所有打开该卷的句柄关闭，
最多 10 秒）再 `FSCTL_DISMOUNT_VOLUME` 把文件系统摘下来，然后才摘盘符、离线磁盘、结束服务、
注销会话。少了这一步，卷一旦在用，Windows 就会用 “The session cannot be logged out since a
device on that session is currently being used.” 拒绝登出，留下只能靠下次挂载清理的残留会话。

盘符、磁盘离线、设备卸载这些步骤已经全部改成直接调 Win32（`crates/vcrs-host/src/win32.rs`：
SCM 服务、`IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`、`SetVolumeMountPointW` /
`DeleteVolumeMountPointW`、`IOCTL_DISK_SET_DISK_ATTRIBUTES`、setupapi + `pnputil`、
`iscsicli` 列会话），不再为每一件小事起一个 PowerShell（每次启动 PowerShell 固定要
0.3–0.7 秒，第一次用 Storage 模块还要 2 秒以上）。实测：经 agent 重新挂载约 1.5 秒，卸载
约 10–11 秒（此前一次挂载/卸载分别是 20–49 秒和 91 秒）。

创建和扩容也走同一套进度：`vcrs create` / `vcrs create-hidden` / `vcrs expand` 在填数据区时每
5% 往 stderr 打一行，Ctrl-C 会在块边界停下并返回 130（`Interrupted`）。半填充的数据区不是
VeraCrypt 认可的“已格式化”卷，所以命令会说明这一点、把文件留给用户处理；`expand` 中途停下可以
安全重跑（新的头部字段只在填充完成后才写入，半长大的文件仍然描述旧尺寸）。实测：192 MiB 全格式化
create 22 秒，128 MiB 容器扩到 256 MiB 约 13 秒。

给程序用的输出是 `--json`（全局参数）：`vcrs list`（会话/后台服务进程/磁盘快照）、`vcrs info`、
`vcrs header`、`vcrs test`、`vcrs device-info`，以及挂载三件套 `vcrs mount`（盘符、Windows 给的磁
盘、以及之后用来卸载的 target；不带 `--letter` 时给出调用方自己登录发起程序所需的信息）、
`vcrs attach`、`vcrs dismount`（释放的盘符、停掉的服务进程、登出的会话、清掉的设备）。给人看的
内容（提权提示、进度行、serve 横幅）全部走 **stderr**，所以 stdout 要么是普通行、要么是一个
JSON 文档，不会混在一起。退出码：0 成功、1 失败、2 命令行错、1223 用户拒绝提权、130 Ctrl-C 中断。
`iscsi-target` 1.0.0 以 `vendor/iscsi-target` 打补丁形式引入（补丁说明见
`vendor/iscsi-target/PATCHES.md`）：

1. 补齐最后一块 Data-In 上的 residual underflow/overflow 标志与 Residual Count
   （RFC 7143 §11.4.5.2；否则 Microsoft 发起程序在“返回字节少于请求长度”的命令上
   直接重置连接，例如 INQUIRY VPD page 0：请求 255、实际 8）；
2. 把 SCSI response/status 从 `specific[]` 挪到真正的 BHS 字节 2/3，并把 Residual Count
   挪到 `specific[24..28]`（原来与状态字节重叠）；
3. INQUIRY 的 RMB（可移动介质）位改为设备可控（`ScsiBlockDevice::removable()`，
   `vcrs mount --removable`）——Windows 的格式化对话框只对可移动介质提供 exFAT。

方案 C（Dokany）**已移除**：`crates/vcrs-mount/src/fs_main.rs`、`dokan`/`dokan-sys`/
`widestring` 依赖、`MountOptions` 与相关脚本都已删除，FAT 实现只剩 `vcrs format`
（在卷内建 FAT 文件系统，不依赖 Dokany）。历史验证记录见 README 的“Compatibility
evidence”表与 git 历史（`dd330e2`、`7a19eb8`）。

验收：`scripts/vc-iscsi-e2e.ps1`（提权）——vc-rs 建卷 → `vcrs mount` 暴露磁盘 →
Microsoft 发起程序登录（静态目标：`iscsicli AddTarget` + `QLoginTarget`）→ Windows 在
该磁盘上格式化 NTFS → 写入文本、子目录文件与 1 MiB 随机文件（比对 SHA-256）→ 卸载 →
真实 VeraCrypt 挂载同一容器并读回全部文件 → `RESULT: ALL OK`。

已知限制：`QAddTargetPortal`（门户扫描）走的是 discovery 会话，上游状态机无法完成
Microsoft 发起程序的多 PDU 登录，因此必须使用静态目标 + `QLoginTarget`；方案 B（ImDisk
proxy）未安装、未验证。
