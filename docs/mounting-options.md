# Mounting non-FAT filesystems — design options

**中文要点 (short version):** Dokany 只能实现“文件系统”，实现不了“裸磁盘”，所以今天挂载层
必须在用户态自己解析卷内文件系统 —— 目前只实现了 FAT。要让 NTFS / exFAT / ReFS 等
Windows 原生文件系统也能用（包括挂载 VeraCrypt 建的 NTFS 卷），有下面四条路，
**推荐 A（iSCSI + Windows 内置发起程序）**，B 作为不写网络栈的备选，
C 是最省事但只读的方案，D 不建议。

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
   `DataArea`/`VolumeDevice`（带 512 字节缓存与写回），让 Dokany 文件系统、
   SCSI 设备、将来的 ImDisk 服务端都复用它，保证扇区语义只有一处实现。
2. **方案 A 原型**：`iscsi-target` + `ScsiBlockDevice for Volume`，
   先用只读挂载一个已有的 NTFS/exFAT 卷验证 Windows 发起程序能认；
   通过后补齐 `vcrs mount --raw`、`iscsicli` 登录/登出、`vcrs dismount`。
3. **验证链**（沿用现在的交叉验证套路）：
   * vc-rs 建卷 → `vcrs mount --raw` → Windows `format Z: /FS:NTFS` + 写文件 →
     卸载 → 真实 VeraCrypt 挂载同一容器，读到这些文件；
   * 反向：VeraCrypt（或 Windows）建的 NTFS 容器 → `vcrs mount --raw` → 用资源管理器读写。
4. **方案 C 的 NTFS 只读**（可选，独立小需求）：给不想装驱动/要管理员的人一条路。
5. **方案 B** 作为备选后端：若 A 的 Windows 互操作受阻，就把同一块设备接到
   ImDisk 管道协议上（前端替换，设备层不变）。

## 参考

* Dokany 能力边界与证据：`docs/research/dokan-mounting.md`
* iSCSI target crate（含 RFC 3720 一致性模型与 Linux 互操作测试）：
  <https://github.com/lawless-m/iscsi-crate>
* ImDisk proxy 说明与 `devio` 参考实现：
  <https://github.com/LTRData/ImDisk>（`devio/devio.c`）
* 只读 NTFS 库：<https://github.com/ColinFinck/ntfs>、
  <https://github.com/SecurityRonin/ntfs-forensic>
