# 分区/设备级就地加密（Non-system in-place encryption of a partition）

本文档记录 VeraCrypt 的分区就地加密算法（读源码所得）与我们已实现的文件级就地加
密的差别、设备侧还需要的 Windows 管道，以及分阶段实施计划。

参考：`C:/Users/yuan/Desktop/VeraCrypt/src/Format/InPlace.c`（下列行号均指该文件）。

## 1. VeraCrypt 的做法

### 1.1 前置检查 `CheckRequirementsForNonSysInPlaceEnc`（InPlace.c:127+ / :240+）

* 设备路径只接受两种形式：`\Device\HarddiskVolumeN` 或 `\Device\HarddiskN\PartitionM`
  （`M != 0`）；`partitionNumber == 0` → `RAW_DEV_NOT_SUPPORTED_FOR_INPLACE_ENC`
  （整个物理盘不支持，必须是分区）。
* 卷必须是**已挂载的 NTFS**：`FSCTL_GET_NTFS_VOLUME_DATA` 失败 →
  `ONLY_NTFS_SUPPORTED_FOR_NONSYS_INPLACE_ENC`；未挂载 →
  `ONLY_MOUNTED_VOL_SUPPORTED_FOR_NONSYS_INPLACE_ENC`。
* 不允许是系统/启动分区（`volumePath` 不能是 Windows 所在卷）。
* `deviceSize >= TC_NONSYS_INPLACE_ENC_MIN_VOL_SIZE`（InPlace.c:63）=
  `TC_TOTAL_VOLUME_HEADERS_SIZE + TC_MIN_NTFS_FS_SIZE * 2` =
  262144 + 2 * (884 * 4096) = **7503872 字节（约 7.16 MiB）**。
* 空闲簇要求：`FreeClusters * BytesPerCluster >= TC_TOTAL_VOLUME_HEADERS_SIZE`（256 KiB），
  否则 `NOT_ENOUGH_FREE_FILESYS_SPACE_FOR_SHRINK`。
* 扇区大小必须 ≤ 4096 且为 512 的倍数。

### 1.2 开始 `EncryptPartitionInPlaceBegin`（InPlace.c:369+）

1. `deviceSize = GetDeviceSize(volumePath)`；
   `dataAreaSize = GetVolumeDataAreaSize(FALSE, deviceSize)` = `deviceSize - 262144`
   （隐藏卷为 `deviceSize - 131072 - 65536`，与文件卷相同）。
2. 用**共享**方式打开设备句柄（注释：不能要求独占，否则后面
   `FSCTL_ALLOW_EXTENDED_DASD_IO` 与卸载都会失败，InPlace.c:433-434），
   然后 `FSCTL_ALLOW_EXTENDED_DASD_IO`（InPlace.c:457）拿到分区的裸扇区访问权
   （NTFS 驱动默认挡住卷尾的“隐藏扇区”）。
3. **收缩文件系统**（InPlace.c:478+）：
   `sizeToShrinkTo = NewFileSysSizeAfterShrink(...)`（InPlace.c:68）= 
   `(NumberSectors * BytesPerSector - 262144) / BytesPerSector`，
   然后 `FSCTL_SHRINK_VOLUME` + `SHRINK_VOLUME_INFORMATION{ShrinkPrepare,
   NewNumberOfSectors}`，成功后 `ShrinkCommit`。
   失败 `ERROR_ACCESS_DENIED`（卷尾还有已分配的簇）时调用
   `MoveClustersBeforeThreshold(dev, deviceName, totalClusterCount - ...)`
   （InPlace.c:2336-2439，用目录遍历 + `FSCTL_GET_RETRIEVAL_POINTERS` +
   `FSCTL_MOVE_FILE` 把文件簇搬到阈值以下，约 100 行）后重试。
4. `DismountFileSystem(...)`：`FSCTL_LOCK_VOLUME` + `FSCTL_DISMOUNT_VOLUME`
   （带重试，InPlace.c:2012+），拿到对分区的独占写权。
5. 写**备份头**（InPlace.c:570-760）：`CreateVolumeHeaderInMemory(...,
   VolumeSize = dataAreaSize, HiddenVolumeSize = 0,
   EncryptedAreaStart = 131072 + dataAreaSize, EncryptedAreaLength = 0,
   flags = TC_HEADER_FLAG_NONSYS_INPLACE_ENC, sectorSize)`
   → 写到 `deviceSize - 131072`；再写 `WriteRandomDataToReservedHeaderAreas`；
   再写一个**假隐藏备份头**到 `deviceSize - 65536`（hiddenVolumeDataSize =
   dataAreaSize，EncryptedAreaStart = 131072 + dataAreaSize，EncryptedAreaLength =
   dataAreaSize）。
6. `OpenBackupHeader` 回读校验。
7. `ConcealNTFS(dev)`（InPlace.c:2058）：把分区**前 8192 字节异或 0xFF**
   （`TC_INITIAL_NTFS_CONCEAL_PORTION_SIZE = 2 * TC_MAX_VOLUME_SECTOR_SIZE`，
   `TC_NTFS_CONCEAL_CONSTANT = 0xFF`），使 Windows 看到一个坏引导扇区而不再碰它；
   写失败时自动异或回来撤销。

### 1.3 加密循环 `EncryptPartitionInPlaceResume`（InPlace.c:749+）

```
remaining = VolumeSize - EncryptedAreaLength          // 还要加密的字节数
while remaining > 0:
    chunk = min(remaining, 2 MiB)                     // TC_MAX_NONSYS_INPLACE_ENC_WORK_CHUNK_SIZE
    unit  = (remaining - chunk + 131072) / 512        // = 目标偏移 / 512
    read  at  EncryptedAreaStart - chunk - 131072     // 源（明文，逻辑偏移比目标低 128 KiB）
    if remaining - chunk < 8192: 前 (8192 - (remaining - chunk)) 字节 ^= 0xFF   // 撤销 conceal
    EncryptDataUnits(buf, unit, chunk / 512)          // XTS，数据单元号取目标偏移
    write at  EncryptedAreaStart - chunk              // 目标（密文）
    EncryptedAreaStart  -= chunk
    EncryptedAreaLength += chunk
    if 自上次写头 >= 64 MiB: FastVolumeHeaderUpdate(...)   // 只更新备份头，盐和密钥不变
```

写失败时：`DecryptDataUnits(buf)` 并把 `buf + 131072` 起 `chunk - 131072` 字节写回源位置
（InPlace.c:1038-1046），保留“可重试”状态。

### 1.4 收尾（InPlace.c:1085+）

* 循环结束后无论是否暂停都先 `FastVolumeHeaderUpdate`（写备份头）。
* 只有真正跑完（未暂停）才写**主头**：`CreateVolumeHeaderInMemory(VolumeSize =
  dataAreaSize, EncryptedAreaStart = masterCryptoInfo->EncryptedAreaStart (= 131072),
  EncryptedAreaLength = VolumeSize, flags | NONSYS_INPLACE_ENC)` → 写到偏移 0，
  接着 `WriteRandomDataToReservedHeaderAreas` 填充保留区，再写假隐藏头到偏移 65536。
  也就是主头组与备份头组的位置和文件卷完全一样。
* 设备**不截断**（分区大小不变）。

### 1.5 解密 `DecryptPartitionInPlace`（InPlace.c:1302+）

自下而上：`remaining = EncryptedAreaLength`；
`chunk = min(remaining, 2 MiB)`；`unit = EncryptedAreaStart / 512`（取**源**偏移）；
读 `EncryptedAreaStart` 处密文 → 解密 → 写到 `EncryptedAreaStart - 131072`；
`EncryptedAreaStart += chunk; EncryptedAreaLength -= chunk;`
最后把 `EncryptedAreaStart` 之后的所有扇区清零（设备不清长度）。conceal 的撤销
在 `workChunkStartByteOffset - 131072 < 8192` 时对缓冲区前若干字节异或 0xFF。

## 2. 与我们已经实现并验证过的文件级就地加密的差别

相同之处（核心算法已经过 VeraCrypt 实测验证）：

* 布局：`EncryptedAreaStart + EncryptedAreaLength` 恒等于 `数据区末尾 + 131072`，
  前者从大到小、后者从小到大；数据单元号 = **目标**偏移 / 512；头字段语义一致。
* 备份头在运行期间是唯一起作用的头；主头只在最后写；每次更新头复用同一盐与密钥；
  完成后 `EncryptedAreaStart = 131072`、`EncryptedAreaLength = dataSize`、标志位保留。
* 隐藏卷不可就地加密；V1 旧格式不可；中断后凭备份头恢复。

设备特有的部分（也就是本任务真正要做的）：

1. **设备 I/O**：打开 `\\.\PhysicalDriveN\PartitionM`（或 `\\.\HarddiskVolumeN`），
   要求管理员权限；读写必须按扇区对齐（我们的 chunk 是 2 MiB、512 对齐，天然满足）；
   `FSCTL_ALLOW_EXTENDED_DASD_IO` 才能读写分区最后 128 KiB 的头区。
2. **设备尺寸与扇区大小**：`GetDeviceSize`（`IOCTL_DISK_GET_LENGTH_INFO` 或
   `GetFileSizeEx`）+ `IOCTL_DISK_GET_DRIVE_GEOMETRY.BytesPerSector`。
3. **收缩文件系统**：`FSCTL_SHRINK_VOLUME`（ShrinkPrepare/ShrinkCommit），
   以及在卷尾簇被占用时搬移簇（`MoveClustersBeforeThreshold`）。
   这是唯一一块工作量与风险都明显更大的部分。
4. **独占**：`FSCTL_LOCK_VOLUME` + `FSCTL_DISMOUNT_VOLUME`。
5. **conceal**：前 8192 字节异或 0xFF 以及循环末尾的撤销（文件级不需要，因为文件
   不会被系统自动挂载）。
6. 结束时不清零、不截断（文件级会把尾部清零并截断成明文镜像）。

## 3. 风险

* 目标分区上可能有真实数据：任何算法错误都会毁掉分区（文件级只毁一个容器文件）。
* 需要管理员权限；打开的是物理设备，写错偏移就是写错盘。
* 收缩与搬移簇涉及 NTFS 内部结构，实现不当会破坏文件系统。
* 系统分区绝对不能作为目标（本轮也不在范围内）。

## 4. 分阶段计划

**阶段 1：只读诊断 `vcrs device-info <device>`（无任何写入）**
* 解析设备路径、打开（只读句柄 + 管理员）、打印：设备大小、扇区大小、
  我们的布局推算（数据区 = 大小 - 262144、备份头位置）、前 512 字节的引导扇区判定、
  `FSCTL_GET_NTFS_VOLUME_DATA` 的 FS 大小/簇大小/空闲簇数；
* 给出可行性结论：是否 ≥ 7503872 字节、是否 NTFS、是否已挂载、是否系统分区、
  FS 需要收缩多少字节、空闲簇是否够 256 KiB；
* 对已经就地加密/解密的设备，报告 `EncryptedAreaStart/Length` 与进度（恢复用）。

**阶段 2：文件系统收缩 `FSCTL_SHRINK_VOLUME`（先做 `--dry-run` 报告，再真收缩）**
* ShrinkPrepare → ShrinkCommit；`ERROR_ACCESS_DENIED` 时给出明确错误并建议
  `defrag <盘符> /X`（空闲空间整合）后重试；
* 搬移簇（`MoveClustersBeforeThreshold`）作为可选后续：先不做，遇到被占用的卷尾就
  明确报错而不是硬来。

**阶段 3：分区加密/解密 `vcrs encrypt-device-in-place <device>` /
`vcrs decrypt-device-in-place <device>`**
* 复用已经验证的循环与头逻辑，改成设备后端；写主头组 + 假隐藏头 + 备份头组；
* 需要显式 `--yes` 与二次确认（默认拒绝执行），拒绝系统分区。

**验证床**：用 Windows 自带的 VHD 做一次性磁盘（`New-VHD -Fixed` →
`Mount-VHD` → `New-Partition` → `Format-Volume -FileSystem NTFS`），
这样得到的是一个**真实的可分区设备**，可以完整跑通：
`vcrs device-info` → 写测试文件 → `encrypt-device-in-place` →
真实 VeraCrypt 挂载该分区并读回文件 → `decrypt-device-in-place` →
文件完好。任何一步出错都只影响这个一次性 VHD。

## 5. 需要确认的取舍

1. 收缩簇搬移（`MoveClustersBeforeThreshold`）现在做还是先只报错？
2. 设备目标形式：`\\.\PhysicalDriveN\PartitionM`（推荐，简单明确）是否够用？
3. 是否需要 GUI 之外的保护措施，例如加密前强制 `--yes` + 打印目标设备信息并要求
   输入设备序号确认？
