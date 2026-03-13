---
title: Docker Public Repo Collection With Region World Collector
description: Docker Public Repo Collection With Region World Collector
navigation:
  icon: i-lucide-container
  title: Docker Public Repo Collection With Region World Collector
---

## Docker Public Repository World Collection :badge[v27.5.1] :badge[2025 Edition] :badge[500+ Sources]

::note{to="https://docs.docker.com/engine/install/"}
The **largest** Docker registry and mirror directory ever compiled. Covers **every continent**, **50+ countries**, and **500+ registry endpoints** with full command outputs, pentesting tools, and configuration for **8 Linux distributions**.
::

::caution
Some mirrors may change URLs or go offline. Always verify before production use. Last verified **June 2025**.
::

## Master Global Registries

::card-group
  ::card
  ---
  title: Docker Hub (Official)
  icon: i-simple-icons-docker
  to: https://hub.docker.com
  target: _blank
  ---
  The **default** global registry with **9.8M+** images.

  `registry-1.docker.io`

  - Anonymous: 100 pulls / 6 hours
  - Authenticated: 200 pulls / 6 hours
  - Pro/Team: Unlimited
  ::

  ::card
  ---
  title: GitHub Container Registry
  icon: i-simple-icons-github
  to: https://github.com/features/packages
  target: _blank
  ---
  GitHub-native OCI registry integrated with Actions and Codespaces.

  `ghcr.io`

  - Free for public images
  - 500MB free storage (private)
  - Integrated with GitHub Actions
  ::

  ::card
  ---
  title: Google Artifact Registry
  icon: i-simple-icons-googlecloud
  to: https://cloud.google.com/artifact-registry
  target: _blank
  ---
  Multi-region, multi-format registry for Docker, Maven, npm, Python.

  `gcr.io` · `us-docker.pkg.dev` · `europe-docker.pkg.dev` · `asia-docker.pkg.dev`
  ::

  ::card
  ---
  title: Amazon ECR Public Gallery
  icon: i-simple-icons-amazonaws
  to: https://gallery.ecr.aws
  target: _blank
  ---
  AWS public gallery with global CloudFront CDN. No auth required.

  `public.ecr.aws`

  - 10 GB free bandwidth / month (anonymous)
  - 200 GB / month (authenticated)
  ::

  ::card
  ---
  title: Quay.io (Red Hat)
  icon: i-simple-icons-redhat
  to: https://quay.io/search
  target: _blank
  ---
  Enterprise registry by Red Hat. Hosts Fedora, CentOS, OpenShift, CoreOS.

  `quay.io`

  - Built-in Clair vulnerability scanning
  - Robot accounts for CI/CD
  ::

  ::card
  ---
  title: Microsoft Container Registry
  icon: i-simple-icons-microsoftazure
  to: https://mcr.microsoft.com
  target: _blank
  ---
  Official Microsoft images — .NET, SQL Server, PowerShell, Azure CLI, Windows.

  `mcr.microsoft.com`

  - No authentication required
  - Global CDN delivery
  ::

  ::card
  ---
  title: GitLab Container Registry
  icon: i-simple-icons-gitlab
  to: https://docs.gitlab.com/user/packages/container_registry/
  target: _blank
  ---
  Integrated with GitLab CI/CD. 5GB free tier. Supports OCI artifacts.

  `registry.gitlab.com`
  ::

  ::card
  ---
  title: Harbor (CNCF)
  icon: i-simple-icons-cncf
  to: https://goharbor.io
  target: _blank
  ---
  Open source cloud native registry. Self-hosted with RBAC, scanning, replication.

  `demo.goharbor.io`
  ::

  ::card
  ---
  title: JFrog Artifactory
  icon: i-simple-icons-jfrog
  to: https://jfrog.com/artifactory/
  target: _blank
  ---
  Universal artifact manager — Docker, Helm, npm, Maven, and 30+ formats.

  `<name>.jfrog.io`
  ::

  ::card
  ---
  title: Nexus Repository (Sonatype)
  icon: i-lucide-database
  to: https://www.sonatype.com/products/sonatype-nexus-repository
  target: _blank
  ---
  Universal repository manager. Docker hosted, proxy, and group repos.

  Self-hosted · Supports Docker, Helm, npm, Maven
  ::

  ::card
  ---
  title: Cloudsmith
  icon: i-lucide-cloud
  to: https://cloudsmith.com
  target: _blank
  ---
  Cloud-native package management as a service.

  `docker.cloudsmith.io`
  ::

  ::card
  ---
  title: DigitalOcean Container Registry
  icon: i-simple-icons-digitalocean
  to: https://www.digitalocean.com/products/container-registry
  target: _blank
  ---
  Simple, affordable container registry. Free tier: 1 repo, 500MB.

  `registry.digitalocean.com`
  ::

  ::card
  ---
  title: Treescale
  icon: i-lucide-tree-pine
  to: https://treescale.com
  target: _blank
  ---
  P2P container image distribution for large-scale deployments.

  `registry.treescale.com`
  ::

  ::card
  ---
  title: Canister.io
  icon: i-lucide-box
  to: https://canister.io
  target: _blank
  ---
  Free private Docker registry. 20 private repos on free tier.

  `cloud.canister.io:5000`
  ::

  ::card
  ---
  title: Oracle Container Registry
  icon: i-lucide-database
  to: https://container-registry.oracle.com
  target: _blank
  ---
  Oracle DB, Java, Linux images. Free with Oracle account.

  `container-registry.oracle.com`
  ::

  ::card
  ---
  title: Vultr Container Registry
  icon: i-lucide-server
  to: https://www.vultr.com/products/container-registry/
  target: _blank
  ---
  Multi-region registry with free egress within Vultr network.

  `<region>.vultrcr.com`
  ::

  ::card
  ---
  title: Codeberg Container Registry
  icon: i-lucide-git-branch
  to: https://codeberg.org
  target: _blank
  ---
  Community-driven, privacy-focused Git hosting with OCI registry.

  `codeberg.org`
  ::
::

---

## World Region Registry Collection

::tabs
  :::tabs-item{icon="i-lucide-globe" label="🇨🇳 China"}

  ::warning
  Docker Hub is **heavily throttled or blocked** in mainland China. Local mirrors are **essential**. Configure multiple mirrors for failover.
  ::

  ### University & Academic Mirrors

  ::card-group
    ::card
    ---
    title: USTC Mirror
    icon: i-lucide-graduation-cap
    to: https://mirrors.ustc.edu.cn/help/dockerhub.html
    target: _blank
    ---
    `https://docker.mirrors.ustc.edu.cn`

    University of Science & Technology of China. One of the fastest and most reliable academic mirrors in China.
    ::

    ::card
    ---
    title: Tsinghua TUNA
    icon: i-lucide-graduation-cap
    to: https://mirrors.tuna.tsinghua.edu.cn/help/docker-ce/
    target: _blank
    ---
    `https://docker.mirrors.tuna.tsinghua.edu.cn`

    Tsinghua University TUNA Association. Excellent bandwidth and uptime.
    ::

    ::card
    ---
    title: SJTU Mirror
    icon: i-lucide-graduation-cap
    to: https://mirror.sjtu.edu.cn
    target: _blank
    ---
    `https://docker.mirrors.sjtug.sjtu.edu.cn`

    Shanghai Jiao Tong University Linux User Group.
    ::

    ::card
    ---
    title: Nanjing University
    icon: i-lucide-graduation-cap
    to: https://mirrors.nju.edu.cn
    target: _blank
    ---
    `https://docker.nju.edu.cn`

    NJU Open Source Mirror. Fast access from East China region.
    ::

    ::card
    ---
    title: BFSU Mirror
    icon: i-lucide-graduation-cap
    to: https://mirrors.bfsu.edu.cn
    target: _blank
    ---
    `https://docker.bfsu.edu.cn`

    Beijing Foreign Studies University. Synced with TUNA.
    ::

    ::card
    ---
    title: Zhejiang University
    icon: i-lucide-graduation-cap
    to: https://mirrors.zju.edu.cn
    target: _blank
    ---
    `https://docker.zju.edu.cn`

    ZJU Mirror Station. Fast in Zhejiang province.
    ::

    ::card
    ---
    title: ISCAS Mirror
    icon: i-lucide-graduation-cap
    to: https://mirror.iscas.ac.cn
    target: _blank
    ---
    `https://mirror.iscas.ac.cn`

    Institute of Software, Chinese Academy of Sciences.
    ::

    ::card
    ---
    title: Harbin Institute of Technology
    icon: i-lucide-graduation-cap
    to: https://mirrors.hit.edu.cn
    target: _blank
    ---
    `https://docker.hit.edu.cn`

    HIT Mirror. Best for Northeast China.
    ::

    ::card
    ---
    title: Lanzhou University
    icon: i-lucide-graduation-cap
    to: https://mirrors.lzu.edu.cn
    target: _blank
    ---
    `https://docker.lzu.edu.cn`

    LZU Mirror. Best for Northwest China.
    ::

    ::card
    ---
    title: Chongqing University of Posts & Telecom
    icon: i-lucide-graduation-cap
    to: https://mirrors.cqupt.edu.cn
    target: _blank
    ---
    `https://docker.cqupt.edu.cn`

    CQUPT Mirror. Best for Southwest China.
    ::

    ::card
    ---
    title: Dalian University of Technology
    icon: i-lucide-graduation-cap
    to: https://mirrors.dlut.edu.cn
    target: _blank
    ---
    `https://docker.dlut.edu.cn`

    DLUT Mirror. Fast in Liaoning province.
    ::

    ::card
    ---
    title: South China University of Technology
    icon: i-lucide-graduation-cap
    to: https://mirrors.scut.edu.cn
    target: _blank
    ---
    `https://docker.scut.edu.cn`

    SCUT Mirror. Best for South China / Guangdong.
    ::
  ::

  ### Cloud Provider Mirrors

  ::card-group
    ::card
    ---
    title: Alibaba Cloud ACR
    icon: i-lucide-cloud
    to: https://cr.console.aliyun.com
    target: _blank
    ---
    `https://registry.cn-hangzhou.aliyuncs.com`

    China's largest cloud. Personal accelerator available via console. Supports all Alibaba regions.
    ::

    ::card
    ---
    title: Tencent Cloud TCR
    icon: i-lucide-cloud
    to: https://cloud.tencent.com/product/tcr
    target: _blank
    ---
    `https://mirror.ccs.tencentyun.com`

    Tencent Cloud Container Registry. Fastest inside Tencent VPC.
    ::

    ::card
    ---
    title: Huawei Cloud SWR
    icon: i-lucide-cloud
    to: https://www.huaweicloud.com/product/swr.html
    target: _blank
    ---
    `https://05f073ad3c0010ea0f4bc00b7105ec20.mirror.swr.myhuaweicloud.com`

    Huawei Cloud Software Repository for Container. Enterprise-grade.
    ::

    ::card
    ---
    title: Baidu Cloud CCR
    icon: i-lucide-cloud
    to: https://cloud.baidu.com/product/ccr.html
    target: _blank
    ---
    `https://mirror.baidubce.com`

    Baidu Cloud Container Registry. Integrated with Baidu AI services.
    ::

    ::card
    ---
    title: JD Cloud
    icon: i-lucide-cloud
    to: https://www.jdcloud.com/cn/products/container-registry
    target: _blank
    ---
    `https://registry.jdcloud.com`

    JD.com Cloud. Fast for e-commerce infrastructure.
    ::

    ::card
    ---
    title: VolcEngine (ByteDance)
    icon: i-lucide-cloud
    to: https://www.volcengine.com/product/cr
    target: _blank
    ---
    `https://mirror.volces.com`

    ByteDance's cloud platform (TikTok parent). Very fast in China.
    ::

    ::card
    ---
    title: UCloud
    icon: i-lucide-cloud
    to: https://www.ucloud.cn
    target: _blank
    ---
    `https://uhub.service.ucloud.cn`

    UCloud Hub. Good for startup deployments.
    ::

    ::card
    ---
    title: QingCloud
    icon: i-lucide-cloud
    to: https://www.qingcloud.com
    target: _blank
    ---
    `https://dockerhub.qingcloud.com`

    QingCloud Docker Hub Mirror. Integrated with KubeSphere.
    ::

    ::card
    ---
    title: Kingsoft Cloud
    icon: i-lucide-cloud
    to: https://www.ksyun.com
    target: _blank
    ---
    `https://hub.kce.ksyun.com`

    Kingsoft Cloud Engine. CDN-backed.
    ::
  ::

  ### Community & Third-Party Mirrors

  ::card-group
    ::card
    ---
    title: DaoCloud Public
    icon: i-lucide-layers
    to: https://www.daocloud.io
    target: _blank
    ---
    `https://docker.m.daocloud.io`

    Largest community Docker mirror in China. Highly reliable.
    ::

    ::card
    ---
    title: DaoCloud Accelerator
    icon: i-lucide-zap
    to: https://www.daocloud.io/mirror
    target: _blank
    ---
    `https://f1361db2.m.daocloud.io`

    DaoCloud personal accelerator. Register for custom URL.
    ::

    ::card
    ---
    title: NetEase 163
    icon: i-lucide-layers
    to: https://c.163.com
    target: _blank
    ---
    `https://hub-mirror.c.163.com`

    NetEase Cloud container mirror. Battle-tested in production.
    ::

    ::card
    ---
    title: 1Panel Mirror
    icon: i-lucide-panel-left
    to: https://1panel.cn
    target: _blank
    ---
    `https://docker.1panel.live`

    1Panel open source server management panel mirror.
    ::

    ::card
    ---
    title: DockerProxy
    icon: i-lucide-arrow-right-left
    to: https://dockerproxy.com
    target: _blank
    ---
    `https://dockerproxy.com`

    Community-maintained Docker Hub proxy. Supports gcr.io, ghcr.io, quay.io.
    ::

    ::card
    ---
    title: DockerPull
    icon: i-lucide-download
    to: https://dockerpull.org
    target: _blank
    ---
    `https://dockerpull.org`

    Community pull-through proxy. Open source.
    ::

    ::card
    ---
    title: Docker CF Workers
    icon: i-lucide-globe
    to: https://docker.cfworkers.org
    target: _blank
    ---
    `https://docker.cfworkers.org`

    Cloudflare Workers-powered Docker proxy. Globally distributed.
    ::

    ::card
    ---
    title: AtomHub
    icon: i-lucide-atom
    to: https://atomhub.openatom.cn
    target: _blank
    ---
    `https://atomhub.openatom.cn`

    OpenAtom Foundation mirror. Enterprise-backed open source.
    ::

    ::card
    ---
    title: Rainbond Mirror
    icon: i-lucide-cloud-rain
    to: https://www.rainbond.com
    target: _blank
    ---
    `https://docker.rainbond.cc`

    Rainbond cloud native platform mirror.
    ::

    ::card
    ---
    title: Coding.net Mirror
    icon: i-lucide-code
    to: https://coding.net
    target: _blank
    ---
    `https://mirrors.coding.net`

    Tencent-owned developer platform mirror.
    ::

    ::card
    ---
    title: Gitee AI Registry
    icon: i-lucide-git-branch
    to: https://gitee.com
    target: _blank
    ---
    `https://ai.gitee.com/registry`

    China's largest Git hosting platform registry.
    ::

    ::card
    ---
    title: Geekery Mirror
    icon: i-lucide-terminal
    to: https://docker.geekery.cn
    target: _blank
    ---
    `https://docker.geekery.cn`

    Community mirror by Chinese developer community.
    ::
  ::

  ### Alibaba Cloud — All Regional Endpoints

  ::collapsible

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="East China"}
    - `registry.cn-hangzhou.aliyuncs.com` — **Hangzhou** (华东1)
    - `registry.cn-shanghai.aliyuncs.com` — **Shanghai** (华东2)
    - `registry.cn-nanjing.aliyuncs.com` — **Nanjing** (华东5)
    - `registry.cn-fuzhou.aliyuncs.com` — **Fuzhou** (华东6)
    - `registry.cn-qingdao.aliyuncs.com` — **Qingdao** (华北1)
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="North China"}
    - `registry.cn-beijing.aliyuncs.com` — **Beijing** (华北2)
    - `registry.cn-zhangjiakou.aliyuncs.com` — **Zhangjiakou** (华北3)
    - `registry.cn-huhehaote.aliyuncs.com` — **Hohhot** (华北5)
    - `registry.cn-wulanchabu.aliyuncs.com` — **Ulanqab** (华北6)
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="South China"}
    - `registry.cn-shenzhen.aliyuncs.com` — **Shenzhen** (华南1)
    - `registry.cn-guangzhou.aliyuncs.com` — **Guangzhou** (华南2)
    - `registry.cn-heyuan.aliyuncs.com` — **Heyuan** (华南3)
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="Central & West China"}
    - `registry.cn-chengdu.aliyuncs.com` — **Chengdu** (西南1)
    - `registry.cn-wuhan-lr.aliyuncs.com` — **Wuhan** (华中1)
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="Special Regions"}
    - `registry.cn-hongkong.aliyuncs.com` — **Hong Kong** (中国香港)
    - `registry.ap-southeast-1.aliyuncs.com` — **Singapore**
    - `registry.ap-southeast-2.aliyuncs.com` — **Sydney**
    - `registry.ap-southeast-3.aliyuncs.com` — **Kuala Lumpur**
    - `registry.ap-southeast-5.aliyuncs.com` — **Jakarta**
    - `registry.ap-southeast-6.aliyuncs.com` — **Manila**
    - `registry.ap-southeast-7.aliyuncs.com` — **Bangkok**
    - `registry.ap-northeast-1.aliyuncs.com` — **Tokyo**
    - `registry.ap-northeast-2.aliyuncs.com` — **Seoul**
    - `registry.ap-south-1.aliyuncs.com` — **Mumbai**
    - `registry.me-east-1.aliyuncs.com` — **Dubai**
    - `registry.eu-central-1.aliyuncs.com` — **Frankfurt**
    - `registry.eu-west-1.aliyuncs.com` — **London**
    - `registry.us-east-1.aliyuncs.com` — **Virginia**
    - `registry.us-west-1.aliyuncs.com` — **Silicon Valley**
    :::
  ::



  ### Tencent Cloud — All Regional Endpoints

  ::collapsible

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="China Mainland"}
    - `ccr.ccs.tencentyun.com` — **Guangzhou / Shanghai / Beijing / Chengdu / Chongqing / Nanjing**
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="International"}
    - `hkccr.ccs.tencentyun.com` — **Hong Kong**
    - `sgccr.ccs.tencentyun.com` — **Singapore**
    - `jpccr.ccs.tencentyun.com` — **Tokyo**
    - `krccr.ccs.tencentyun.com` — **Seoul**
    - `inccr.ccs.tencentyun.com` — **Mumbai**
    - `thccr.ccs.tencentyun.com` — **Bangkok**
    - `deccr.ccs.tencentyun.com` — **Frankfurt**
    - `uswccr.ccs.tencentyun.com` — **Silicon Valley**
    - `caccr.ccs.tencentyun.com` — **Toronto**
    - `saoccr.ccs.tencentyun.com` — **São Paulo**
    :::
  ::

  ::

  :::

  :::tabs-item{icon="i-lucide-globe" label="🇯🇵 Japan & 🇰🇷 Korea"}

  ### Japan :badge[13 Sources]

  ::card-group
    ::card
    ---
    title: Google Asia Northeast 1
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry/docs/repositories/repo-locations
    target: _blank
    ---
    `asia-northeast1-docker.pkg.dev`

    Google Cloud Tokyo region. Low latency for Japan-based workloads.
    ::

    ::card
    ---
    title: Google Asia Northeast 2
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry/docs/repositories/repo-locations
    target: _blank
    ---
    `asia-northeast2-docker.pkg.dev`

    Google Cloud Osaka region.
    ::

    ::card
    ---
    title: AWS ECR Tokyo
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-northeast-1.amazonaws.com`

    AWS Elastic Container Registry — ap-northeast-1 (Tokyo).
    ::

    ::card
    ---
    title: AWS ECR Osaka
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-northeast-3.amazonaws.com`

    AWS ECR — ap-northeast-3 (Osaka).
    ::

    ::card
    ---
    title: Azure Japan East
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (Japan East)

    Azure Container Registry in Tokyo.
    ::

    ::card
    ---
    title: Oracle Cloud Tokyo
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `nrt.ocir.io`

    Oracle Cloud Infrastructure Registry — Narita / Tokyo.
    ::

    ::card
    ---
    title: Oracle Cloud Osaka
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `kix.ocir.io`

    Oracle Cloud Infrastructure Registry — Kansai / Osaka.
    ::

    ::card
    ---
    title: IIJ GIO
    icon: i-lucide-server
    to: https://www.iij.ad.jp/en/
    target: _blank
    ---
    `registry.gw.iij.jp`

    IIJ (Internet Initiative Japan) private cloud registry.
    ::

    ::card
    ---
    title: SAKURA Cloud
    icon: i-lucide-server
    to: https://cloud.sakura.ad.jp
    target: _blank
    ---
    `registry.sakura.io`

    SAKURA internet cloud. Popular for indie developers in Japan.
    ::

    ::card
    ---
    title: IDC Frontier
    icon: i-lucide-server
    to: https://www.idcf.jp
    target: _blank
    ---
    `registry.idcf.jp`

    IDC Frontier (Yahoo Japan subsidiary) cloud registry.
    ::

    ::card
    ---
    title: NTT Communications
    icon: i-lucide-server
    to: https://www.ntt.com
    target: _blank
    ---
    `registry.ecl.ntt.com`

    NTT Enterprise Cloud registry.
    ::

    ::card
    ---
    title: Alibaba Japan
    icon: i-lucide-cloud
    to: https://www.alibabacloud.com/product/container-registry
    target: _blank
    ---
    `registry.ap-northeast-1.aliyuncs.com`

    Alibaba Cloud Japan region.
    ::

    ::card
    ---
    title: Tencent Japan
    icon: i-lucide-cloud
    to: https://cloud.tencent.com/product/tcr
    target: _blank
    ---
    `jpccr.ccs.tencentyun.com`

    Tencent Cloud Tokyo region.
    ::
  ::

  ### South Korea :badge[11 Sources]

  ::card-group
    ::card
    ---
    title: Kakao Mirror
    icon: i-lucide-message-circle
    to: https://mirror.kakao.com
    target: _blank
    ---
    `https://mirror.kakao.com`

    Kakao Corp. community mirror. The most popular Docker mirror in Korea.
    ::

    ::card
    ---
    title: NHN Cloud
    icon: i-lucide-cloud
    to: https://www.nhncloud.com
    target: _blank
    ---
    `registry.nhncloud.com`

    NHN Corporation cloud registry.
    ::

    ::card
    ---
    title: AWS ECR Seoul
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-northeast-2.amazonaws.com`

    AWS ECR — ap-northeast-2 (Seoul).
    ::

    ::card
    ---
    title: Google Cloud Seoul
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `asia-northeast3-docker.pkg.dev`

    Google Artifact Registry — Seoul region.
    ::

    ::card
    ---
    title: Naver Cloud
    icon: i-lucide-cloud
    to: https://www.ncloud.com
    target: _blank
    ---
    `registry.navercorp.com`

    Naver Cloud Platform container registry.
    ::

    ::card
    ---
    title: KT Cloud
    icon: i-lucide-cloud
    to: https://cloud.kt.com
    target: _blank
    ---
    `registry.kt.com`

    KT Corporation cloud registry.
    ::

    ::card
    ---
    title: Samsung SDS
    icon: i-lucide-building
    to: https://www.samsungsds.com
    target: _blank
    ---
    `registry.samsungsds.com`

    Samsung SDS enterprise container registry.
    ::

    ::card
    ---
    title: Oracle Cloud Seoul
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `icn.ocir.io`

    Oracle Cloud — Incheon / Seoul.
    ::

    ::card
    ---
    title: Alibaba Korea
    icon: i-lucide-cloud
    to: https://www.alibabacloud.com/product/container-registry
    target: _blank
    ---
    `registry.ap-northeast-2.aliyuncs.com`

    Alibaba Cloud Korea region.
    ::

    ::card
    ---
    title: Tencent Korea
    icon: i-lucide-cloud
    to: https://cloud.tencent.com/product/tcr
    target: _blank
    ---
    `krccr.ccs.tencentyun.com`

    Tencent Cloud Seoul region.
    ::

    ::card
    ---
    title: Azure Korea Central
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (Korea Central)

    Azure Container Registry — Seoul.
    ::
  ::

  :::

  :::tabs-item{icon="i-lucide-globe" label="🌏 SE Asia & 🇮🇳 India"}

  ### Singapore :badge[10 Sources]

  ::card-group
    ::card
    ---
    title: AWS ECR Singapore
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-southeast-1.amazonaws.com`

    AWS ECR — ap-southeast-1 (Singapore).
    ::

    ::card
    ---
    title: Google Asia SE1
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `asia-southeast1-docker.pkg.dev`

    Google Artifact Registry — Singapore.
    ::

    ::card
    ---
    title: Alibaba Singapore
    icon: i-lucide-cloud
    to: https://www.alibabacloud.com/product/container-registry
    target: _blank
    ---
    `registry.ap-southeast-1.aliyuncs.com`

    Alibaba Cloud Singapore.
    ::

    ::card
    ---
    title: Oracle Cloud Singapore
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `sin.ocir.io`

    Oracle Cloud — Singapore.
    ::

    ::card
    ---
    title: Azure Southeast Asia
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (Southeast Asia)

    Azure Container Registry — Singapore.
    ::

    ::card
    ---
    title: DigitalOcean SGP1
    icon: i-simple-icons-digitalocean
    to: https://www.digitalocean.com/products/container-registry
    target: _blank
    ---
    `registry.digitalocean.com` (SGP1)

    DigitalOcean Singapore datacenter.
    ::

    ::card
    ---
    title: Tencent Singapore
    icon: i-lucide-cloud
    to: https://cloud.tencent.com/product/tcr
    target: _blank
    ---
    `sgccr.ccs.tencentyun.com`

    Tencent Cloud Singapore.
    ::

    ::card
    ---
    title: Vultr Singapore
    icon: i-lucide-server
    to: https://www.vultr.com/products/container-registry/
    target: _blank
    ---
    `sgp.vultrcr.com`

    Vultr Container Registry — Singapore.
    ::

    ::card
    ---
    title: Linode Singapore
    icon: i-lucide-server
    to: https://www.linode.com
    target: _blank
    ---
    `registry.linode.com` (ap-south)

    Akamai / Linode Singapore region.
    ::

    ::card
    ---
    title: Upcloud Singapore
    icon: i-lucide-server
    to: https://upcloud.com
    target: _blank
    ---
    `hub.upcloud.com` (SGP)

    UpCloud Singapore region.
    ::
  ::

  ### Indonesia, Thailand, Vietnam, Malaysia, Philippines

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="🇮🇩 Indonesia (5 Sources)"}
    - `<acct>.dkr.ecr.ap-southeast-3.amazonaws.com` — **AWS ECR Jakarta**
    - `registry.ap-southeast-5.aliyuncs.com` — **Alibaba Cloud Jakarta**
    - `asia-southeast2-docker.pkg.dev` — **Google Cloud Jakarta**
    - `registry.biznetgio.com` — **Biznet Gio Cloud**
    - `registry.idcloudhost.com` — **IDCloudHost**
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇹🇭 Thailand (4 Sources)"}
    - `thccr.ccs.tencentyun.com` — **Tencent Cloud Bangkok**
    - `<acct>.dkr.ecr.ap-southeast-7.amazonaws.com` — **AWS ECR Bangkok**
    - `registry.ap-southeast-7.aliyuncs.com` — **Alibaba Cloud Thailand**
    - Google Cloud Thailand — *Coming soon*
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇻🇳 Vietnam (4 Sources)"}
    - `registry.viettelidc.com.vn` — **Viettel IDC**
    - `registry.fptcloud.com` — **FPT Cloud**
    - `registry.cmctelecom.vn` — **CMC Telecom**
    - DigitalOcean via SGP1 — *Nearest POP*
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇲🇾 Malaysia (4 Sources)"}
    - `<acct>.dkr.ecr.ap-southeast-5.amazonaws.com` — **AWS ECR Kuala Lumpur**
    - `registry.ap-southeast-3.aliyuncs.com` — **Alibaba Cloud KL**
    - `registry.tm.com.my` — **Telekom Malaysia**
    - Google Cloud via Singapore — *Nearest region*
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇵🇭 Philippines (3 Sources)"}
    - `registry.ap-southeast-6.aliyuncs.com` — **Alibaba Cloud Manila**
    - AWS ECR via ap-southeast-1 — *Nearest region*
    - Google Cloud via asia-southeast1 — *Nearest region*
    :::
  ::

  ### India :badge[15 Sources]

  ::card-group
    ::card
    ---
    title: AWS ECR Mumbai
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-south-1.amazonaws.com`

    AWS ECR — ap-south-1 (Mumbai). Primary India region.
    ::

    ::card
    ---
    title: AWS ECR Hyderabad
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-south-2.amazonaws.com`

    AWS ECR — ap-south-2 (Hyderabad). Newer India region.
    ::

    ::card
    ---
    title: Google Cloud Mumbai
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `asia-south1-docker.pkg.dev`

    Google Artifact Registry — Mumbai.
    ::

    ::card
    ---
    title: Google Cloud Delhi
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `asia-south2-docker.pkg.dev`

    Google Artifact Registry — Delhi NCR.
    ::

    ::card
    ---
    title: Azure Central India
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (Central India — Pune)

    Azure Container Registry — Central India.
    ::

    ::card
    ---
    title: Oracle Cloud Mumbai
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `bom.ocir.io`

    Oracle Cloud — Bombay / Mumbai.
    ::

    ::card
    ---
    title: Oracle Cloud Hyderabad
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `hyd.ocir.io`

    Oracle Cloud — Hyderabad.
    ::

    ::card
    ---
    title: Alibaba India
    icon: i-lucide-cloud
    to: https://www.alibabacloud.com/product/container-registry
    target: _blank
    ---
    `registry.ap-south-1.aliyuncs.com`

    Alibaba Cloud Mumbai region.
    ::

    ::card
    ---
    title: Tencent Mumbai
    icon: i-lucide-cloud
    to: https://cloud.tencent.com/product/tcr
    target: _blank
    ---
    `inccr.ccs.tencentyun.com`

    Tencent Cloud Mumbai region.
    ::

    ::card
    ---
    title: DigitalOcean Bangalore
    icon: i-simple-icons-digitalocean
    to: https://www.digitalocean.com/products/container-registry
    target: _blank
    ---
    `registry.digitalocean.com` (BLR1)

    DigitalOcean Bangalore datacenter.
    ::
  ::

  :::

  :::tabs-item{icon="i-lucide-globe" label="🇪🇺 Europe"}

  ### Western Europe :badge[45+ Sources]

  ::accordion
    :::accordion-item{icon="i-simple-icons-amazonaws" label="AWS ECR — All Europe Regions (8)"}
    - `<acct>.dkr.ecr.eu-west-1.amazonaws.com` — **Ireland**
    - `<acct>.dkr.ecr.eu-west-2.amazonaws.com` — **London**
    - `<acct>.dkr.ecr.eu-west-3.amazonaws.com` — **Paris**
    - `<acct>.dkr.ecr.eu-central-1.amazonaws.com` — **Frankfurt**
    - `<acct>.dkr.ecr.eu-central-2.amazonaws.com` — **Zurich**
    - `<acct>.dkr.ecr.eu-south-1.amazonaws.com` — **Milan**
    - `<acct>.dkr.ecr.eu-south-2.amazonaws.com` — **Spain**
    - `<acct>.dkr.ecr.eu-north-1.amazonaws.com` — **Stockholm**
    :::

    :::accordion-item{icon="i-simple-icons-googlecloud" label="Google Artifact Registry — All Europe (12)"}
    - `europe-west1-docker.pkg.dev` — **Belgium**
    - `europe-west2-docker.pkg.dev` — **London**
    - `europe-west3-docker.pkg.dev` — **Frankfurt**
    - `europe-west4-docker.pkg.dev` — **Netherlands**
    - `europe-west6-docker.pkg.dev` — **Zurich**
    - `europe-west8-docker.pkg.dev` — **Milan**
    - `europe-west9-docker.pkg.dev` — **Paris**
    - `europe-west10-docker.pkg.dev` — **Berlin**
    - `europe-west12-docker.pkg.dev` — **Turin**
    - `europe-southwest1-docker.pkg.dev` — **Madrid**
    - `europe-north1-docker.pkg.dev` — **Finland**
    - `europe-central2-docker.pkg.dev` — **Warsaw**
    :::

    :::accordion-item{icon="i-simple-icons-microsoftazure" label="Azure ACR — All Europe (12)"}
    - `<name>.azurecr.io` — **West Europe** (Netherlands)
    - `<name>.azurecr.io` — **North Europe** (Ireland)
    - `<name>.azurecr.io` — **UK South** (London)
    - `<name>.azurecr.io` — **UK West** (Cardiff)
    - `<name>.azurecr.io` — **France Central** (Paris)
    - `<name>.azurecr.io` — **France South** (Marseille)
    - `<name>.azurecr.io` — **Germany West Central** (Frankfurt)
    - `<name>.azurecr.io` — **Switzerland North** (Zurich)
    - `<name>.azurecr.io` — **Italy North** (Milan)
    - `<name>.azurecr.io` — **Spain Central** (Madrid)
    - `<name>.azurecr.io` — **Norway East** (Oslo)
    - `<name>.azurecr.io` — **Sweden Central** (Gävle)
    :::

    :::accordion-item{icon="i-lucide-database" label="Oracle Cloud — All Europe (8)"}
    - `fra.ocir.io` — **Frankfurt**
    - `lhr.ocir.io` — **London**
    - `ams.ocir.io` — **Amsterdam**
    - `zrh.ocir.io` — **Zurich**
    - `cdg.ocir.io` — **Paris**
    - `lin.ocir.io` — **Milan**
    - `mad.ocir.io` — **Madrid**
    - `arn.ocir.io` — **Stockholm**
    :::

    :::accordion-item{icon="i-lucide-server" label="European Cloud Providers (10+)"}
    - `<name>.gra7.container-registry.ovh.net` — **OVH France**
    - `<name>.sbg5.container-registry.ovh.net` — **OVH Strasbourg**
    - `<name>.bhs.container-registry.ovh.net` — **OVH Canada**
    - `<name>.waw.container-registry.ovh.net` — **OVH Poland**
    - `rg.fr-par.scw.cloud` — **Scaleway Paris**
    - `rg.nl-ams.scw.cloud` — **Scaleway Amsterdam**
    - `rg.pl-waw.scw.cloud` — **Scaleway Warsaw**
    - `registry.hetzner.cloud` — **Hetzner Germany & Finland**
    - `registry.de-fra.ionos.com` — **IONOS Frankfurt**
    - `registry.de-txl.ionos.com` — **IONOS Berlin**
    - `registry.gb-lhr.ionos.com` — **IONOS London**
    - `registry.es-vit.ionos.com` — **IONOS Spain**
    - `sos-ch-gva-2.exo.io` — **Exoscale Geneva**
    - `registry.infomaniak.com` — **Infomaniak Geneva**
    - `hub.upcloud.com` — **UpCloud Finland**
    :::
  ::

  ### Russia & Eastern Europe :badge[12 Sources]

  ::card-group
    ::card
    ---
    title: Yandex Cloud
    icon: i-lucide-cloud
    to: https://yandex.cloud/en/services/container-registry
    target: _blank
    ---
    `cr.yandex`

    Russia's largest cloud. Supports Docker and OCI. Mirror at `cr.yandex/mirror`.
    ::

    ::card
    ---
    title: VK Cloud
    icon: i-lucide-cloud
    to: https://mcs.mail.ru
    target: _blank
    ---
    `registry.infra.mail.ru`

    VK (Mail.ru Group) Cloud Solutions.
    ::

    ::card
    ---
    title: Selectel
    icon: i-lucide-server
    to: https://selectel.ru
    target: _blank
    ---
    `cr.selcloud.ru`

    Selectel Cloud — Russia's oldest IaaS provider.
    ::

    ::card
    ---
    title: SberCloud
    icon: i-lucide-building
    to: https://sbercloud.ru
    target: _blank
    ---
    `cr.ai.cloud.sbercloud.ru`

    SberCloud — Sberbank's cloud platform.
    ::

    ::card
    ---
    title: MTS Cloud
    icon: i-lucide-cloud
    to: https://cloud.mts.ru
    target: _blank
    ---
    `registry.cloud.mts.ru`

    MTS Cloud — Russia's largest telecom cloud.
    ::

    ::card
    ---
    title: Beeline Cloud
    icon: i-lucide-cloud
    to: https://cloud.beeline.ru
    target: _blank
    ---
    `registry.beeline.ru`

    Beeline Cloud Platform.
    ::

    ::card
    ---
    title: REG.RU Cloud
    icon: i-lucide-server
    to: https://reg.ru
    target: _blank
    ---
    `registry.reg.ru`

    REG.RU domain and cloud services.
    ::

    ::card
    ---
    title: Rostelecom
    icon: i-lucide-building
    to: https://rt.ru
    target: _blank
    ---
    `registry.rt.ru`

    Rostelecom state telecom cloud.
    ::
  ::

  :::

  :::tabs-item{icon="i-lucide-globe" label="🌎 Americas"}

  ### United States :badge[35+ Sources]

  ::accordion
    :::accordion-item{icon="i-simple-icons-docker" label="Docker Hub & Major Registries (8)"}
    - [`registry-1.docker.io`](https://hub.docker.com) — **Docker Hub** (default global)
    - [`ghcr.io`](https://github.com/features/packages) — **GitHub Container Registry**
    - [`quay.io`](https://quay.io) — **Quay.io** (Red Hat)
    - [`registry.gitlab.com`](https://gitlab.com) — **GitLab Registry**
    - [`public.ecr.aws`](https://gallery.ecr.aws) — **AWS ECR Public Gallery**
    - [`mcr.microsoft.com`](https://mcr.microsoft.com) — **Microsoft MCR**
    - [`<name>.jfrog.io`](https://jfrog.com) — **JFrog Artifactory**
    - [`docker.cloudsmith.io`](https://cloudsmith.com) — **Cloudsmith**
    :::

    :::accordion-item{icon="i-simple-icons-amazonaws" label="AWS ECR — All US Regions (4)"}
    - `<acct>.dkr.ecr.us-east-1.amazonaws.com` — **N. Virginia**
    - `<acct>.dkr.ecr.us-east-2.amazonaws.com` — **Ohio**
    - `<acct>.dkr.ecr.us-west-1.amazonaws.com` — **N. California**
    - `<acct>.dkr.ecr.us-west-2.amazonaws.com` — **Oregon**
    :::

    :::accordion-item{icon="i-simple-icons-googlecloud" label="Google Artifact Registry — All US Regions (8)"}
    - `us-docker.pkg.dev` — **US Multi-region**
    - `us-central1-docker.pkg.dev` — **Iowa**
    - `us-east1-docker.pkg.dev` — **South Carolina**
    - `us-east4-docker.pkg.dev` — **N. Virginia**
    - `us-east5-docker.pkg.dev` — **Columbus**
    - `us-west1-docker.pkg.dev` — **Oregon**
    - `us-west2-docker.pkg.dev` — **Los Angeles**
    - `us-west3-docker.pkg.dev` — **Salt Lake City**
    - `us-west4-docker.pkg.dev` — **Las Vegas**
    - `us-south1-docker.pkg.dev` — **Dallas**
    :::

    :::accordion-item{icon="i-lucide-database" label="Oracle Cloud — All US Regions (4)"}
    - `iad.ocir.io` — **Ashburn** (Virginia)
    - `phx.ocir.io` — **Phoenix** (Arizona)
    - `sjc.ocir.io` — **San Jose** (California)
    - `ord.ocir.io` — **Chicago** (Illinois)
    :::

    :::accordion-item{icon="i-lucide-server" label="Other US Registries (6)"}
    - [`registry.digitalocean.com`](https://www.digitalocean.com/products/container-registry) — **DigitalOcean** (NYC / SFO)
    - `sjc.vultrcr.com` — **Vultr** (Silicon Valley)
    - [`registry.linode.com`](https://www.linode.com) — **Akamai / Linode**
    - [`demo.goharbor.io`](https://goharbor.io) — **Harbor Demo**
    - [`registry.treescale.com`](https://treescale.com) — **Treescale**
    - `cloud.canister.io:5000` — **Canister.io**
    :::
  ::

  ### Canada :badge[10 Sources]

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="All Canada Sources"}
    - `<acct>.dkr.ecr.ca-central-1.amazonaws.com` — **AWS ECR Montreal**
    - `<acct>.dkr.ecr.ca-west-1.amazonaws.com` — **AWS ECR Calgary**
    - `northamerica-northeast1-docker.pkg.dev` — **Google Cloud Montreal**
    - `northamerica-northeast2-docker.pkg.dev` — **Google Cloud Toronto**
    - `<name>.azurecr.io` (Canada Central) — **Azure**
    - `<name>.azurecr.io` (Canada East) — **Azure**
    - `yul.ocir.io` — **Oracle Cloud Montreal**
    - `yyz.ocir.io` — **Oracle Cloud Toronto**
    - `<name>.bhs.container-registry.ovh.ca` — **OVH Canada**
    - `caccr.ccs.tencentyun.com` — **Tencent Toronto**
    :::
  ::

  ### South America :badge[9 Sources]

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="All South America Sources"}
    - `<acct>.dkr.ecr.sa-east-1.amazonaws.com` — **AWS ECR São Paulo**
    - `southamerica-east1-docker.pkg.dev` — **Google Cloud São Paulo**
    - `southamerica-west1-docker.pkg.dev` — **Google Cloud Santiago**
    - `<name>.azurecr.io` (Brazil South) — **Azure São Paulo**
    - `gru.ocir.io` — **Oracle Cloud São Paulo**
    - `scl.ocir.io` — **Oracle Cloud Santiago**
    - `vcp.ocir.io` — **Oracle Cloud Vinhedo**
    - `saoccr.ccs.tencentyun.com` — **Tencent São Paulo**
    - Regional endpoint — **Alibaba Brazil**
    :::
  ::

  ### Mexico & Central America :badge[4 Sources]

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="All Mexico Sources"}
    - `northamerica-south1-docker.pkg.dev` — **Google Cloud Mexico**
    - `<name>.azurecr.io` (Mexico Central) — **Azure Mexico**
    - `qro.ocir.io` — **Oracle Cloud Querétaro**
    - AWS ECR via `us-east-1` — *Nearest region*
    :::
  ::

  :::

  :::tabs-item{icon="i-lucide-globe" label="🕌 Middle East"}

  ### UAE / Dubai :badge[7 Sources]

  ::card-group
    ::card
    ---
    title: AWS ECR UAE
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.me-central-1.amazonaws.com`

    AWS ECR — me-central-1 (UAE).
    ::

    ::card
    ---
    title: Azure UAE North
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (UAE North — Dubai)
    ::

    ::card
    ---
    title: Oracle Cloud Dubai
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `dxb.ocir.io`

    Oracle Cloud — Dubai.
    ::

    ::card
    ---
    title: Alibaba ME East
    icon: i-lucide-cloud
    to: https://www.alibabacloud.com/product/container-registry
    target: _blank
    ---
    `registry.me-east-1.aliyuncs.com`

    Alibaba Cloud Dubai.
    ::

    ::card
    ---
    title: Google ME Central1
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `me-central1-docker.pkg.dev`

    Google Cloud — Doha, Qatar.
    ::

    ::card
    ---
    title: Google ME Central2
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `me-central2-docker.pkg.dev`

    Google Cloud — Dammam, Saudi Arabia.
    ::

    ::card
    ---
    title: Google ME West1
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `me-west1-docker.pkg.dev`

    Google Cloud — Tel Aviv.
    ::
  ::

  ### Iran :badge[6 Sources]

  ::card-group
    ::card
    ---
    title: Arvan Cloud
    icon: i-lucide-cloud
    to: https://www.arvancloud.ir
    target: _blank
    ---
    `cr.arvan.land`

    Iran's largest CDN and cloud provider.
    ::

    ::card
    ---
    title: Arvan Docker Mirror
    icon: i-lucide-arrow-right-left
    to: https://www.arvancloud.ir
    target: _blank
    ---
    `https://docker.arvancloud.ir`

    Arvan's Docker Hub mirror for Iran.
    ::

    ::card
    ---
    title: Sotoon Cloud
    icon: i-lucide-cloud
    to: https://sotoon.ir
    target: _blank
    ---
    `registry.sotoon.ir`

    Sotoon Kubernetes platform registry.
    ::

    ::card
    ---
    title: Parspack
    icon: i-lucide-server
    to: https://parspack.com
    target: _blank
    ---
    `registry.parspack.com`

    Parspack hosting and cloud.
    ::

    ::card
    ---
    title: Hamravesh
    icon: i-lucide-cloud
    to: https://hamravesh.com
    target: _blank
    ---
    `registry.hamdocker.ir`

    Hamravesh PaaS platform.
    ::

    ::card
    ---
    title: Community IR Mirror
    icon: i-lucide-users
    to: https://docker.ir
    target: _blank
    ---
    `registry.arvandocker.ir`

    Community-maintained Docker mirror for Iran.
    ::
  ::

  ### Other Middle East

  ::accordion
    :::accordion-item{icon="i-lucide-map-pin" label="🇧🇭 Bahrain (2 Sources)"}
    - `<acct>.dkr.ecr.me-south-1.amazonaws.com` — **AWS ECR Bahrain**
    - `jed.ocir.io` — **Oracle Cloud Jeddah**
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇸🇦 Saudi Arabia (3 Sources)"}
    - `me-central2-docker.pkg.dev` — **Google Cloud Dammam**
    - `registry.stc.com.sa` — **STC Cloud**
    - Alibaba ME Regional — **Alibaba**
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇹🇷 Turkey (3 Sources)"}
    - `registry.turkcell.com.tr` — **Turkcell Cloud**
    - `registry.buluttelekom.com.tr` — **Türk Telekom Cloud**
    - AWS ECR via `eu-central-1` — *Nearest region*
    :::

    :::accordion-item{icon="i-lucide-map-pin" label="🇮🇱 Israel (3 Sources)"}
    - `<acct>.dkr.ecr.il-central-1.amazonaws.com` — **AWS ECR Tel Aviv**
    - `me-west1-docker.pkg.dev` — **Google Cloud Tel Aviv**
    - `mct.ocir.io` — **Oracle Cloud Jerusalem**
    :::
  ::

  :::

  :::tabs-item{icon="i-lucide-globe" label="🌍 Africa & 🌏 Oceania"}

  ### Africa :badge[7 Sources]

  ::card-group
    ::card
    ---
    title: AWS ECR Cape Town
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.af-south-1.amazonaws.com`

    AWS ECR — af-south-1 (Cape Town). Only AWS region in Africa.
    ::

    ::card
    ---
    title: Google Africa South1
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `africa-south1-docker.pkg.dev`

    Google Cloud — Johannesburg.
    ::

    ::card
    ---
    title: Azure South Africa North
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (South Africa North — Johannesburg)
    ::

    ::card
    ---
    title: Azure South Africa West
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (South Africa West — Cape Town)
    ::

    ::card
    ---
    title: Oracle Cloud Johannesburg
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `jnb.ocir.io`

    Oracle Cloud — Johannesburg.
    ::

    ::card
    ---
    title: MainOne (Nigeria)
    icon: i-lucide-server
    to: https://www.mainone.net
    target: _blank
    ---
    `registry.mainone.net`

    MainOne / Equinix — West Africa.
    ::

    ::card
    ---
    title: Safaricom Cloud (Kenya)
    icon: i-lucide-cloud
    to: https://www.safaricom.co.ke
    target: _blank
    ---
    `registry.safaricom.co.ke`

    Safaricom — East Africa.
    ::
  ::

  ### Oceania :badge[12 Sources]

  ::card-group
    ::card
    ---
    title: AWS ECR Sydney
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-southeast-2.amazonaws.com`

    AWS ECR — ap-southeast-2 (Sydney).
    ::

    ::card
    ---
    title: AWS ECR Melbourne
    icon: i-simple-icons-amazonaws
    to: https://docs.aws.amazon.com/general/latest/gr/ecr.html
    target: _blank
    ---
    `<acct>.dkr.ecr.ap-southeast-4.amazonaws.com`

    AWS ECR — ap-southeast-4 (Melbourne).
    ::

    ::card
    ---
    title: Google Cloud Sydney
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `australia-southeast1-docker.pkg.dev`

    Google Artifact Registry — Sydney.
    ::

    ::card
    ---
    title: Google Cloud Melbourne
    icon: i-simple-icons-googlecloud
    to: https://cloud.google.com/artifact-registry
    target: _blank
    ---
    `australia-southeast2-docker.pkg.dev`

    Google Artifact Registry — Melbourne.
    ::

    ::card
    ---
    title: Azure Australia East
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (Australia East — NSW)
    ::

    ::card
    ---
    title: Azure Australia Southeast
    icon: i-simple-icons-microsoftazure
    to: https://azure.microsoft.com/en-us/products/container-registry
    target: _blank
    ---
    `<name>.azurecr.io` (Australia Southeast — Victoria)
    ::

    ::card
    ---
    title: Oracle Cloud Sydney
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `syd.ocir.io`

    Oracle Cloud — Sydney.
    ::

    ::card
    ---
    title: Oracle Cloud Melbourne
    icon: i-lucide-database
    to: https://container-registry.oracle.com
    target: _blank
    ---
    `mel.ocir.io`

    Oracle Cloud — Melbourne.
    ::

    ::card
    ---
    title: DigitalOcean Sydney
    icon: i-simple-icons-digitalocean
    to: https://www.digitalocean.com/products/container-registry
    target: _blank
    ---
    `registry.digitalocean.com` (SYD1)

    DigitalOcean Sydney datacenter.
    ::

    ::card
    ---
    title: Vultr Sydney
    icon: i-lucide-server
    to: https://www.vultr.com/products/container-registry/
    target: _blank
    ---
    `syd.vultrcr.com`

    Vultr Container Registry — Sydney.
    ::

    ::card
    ---
    title: Catalyst Cloud NZ
    icon: i-lucide-cloud
    to: https://catalystcloud.nz
    target: _blank
    ---
    `registry.catalystcloud.nz`

    Catalyst Cloud — New Zealand. NZ-owned.
    ::

    ::card
    ---
    title: Alibaba Sydney
    icon: i-lucide-cloud
    to: https://www.alibabacloud.com/product/container-registry
    target: _blank
    ---
    `registry.ap-southeast-2.aliyuncs.com`

    Alibaba Cloud Sydney.
    ::
  ::

  :::


---

## How to Add Docker Repository Source in Linux

::caution
Incorrect `daemon.json` syntax can **break Docker entirely**. Always back up before editing. Use `python3 -m json.tool` to validate JSON.
::

### Understanding Docker Registry Configuration

::accordion
  :::accordion-item{icon="i-lucide-circle-help" label="What is /etc/docker/daemon.json?"}
  The `/etc/docker/daemon.json` file is Docker's **primary configuration file**. It controls how the Docker daemon operates — registry mirrors, storage drivers, logging, DNS, network settings, and security. Changes require `systemctl daemon-reload && systemctl restart docker`.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="What is a registry mirror?"}
  A registry mirror is a **pull-through cache** that proxies Docker Hub. When you `docker pull nginx`, Docker checks the mirror first. If cached, it serves locally — **faster** and **no rate limits**. Mirrors only work for Docker Hub images.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="What is an insecure registry?"}
  An insecure registry uses **HTTP** instead of HTTPS. Docker refuses HTTP connections by default. Add to `insecure-registries` only for trusted local/private registries. **Never in production**.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Can I use multiple mirrors?"}
  Yes. Docker tries mirrors **in order**. First mirror → second mirror → ... → Docker Hub directly. Multiple mirrors provide **failover** and **reliability**.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="What about authentication?"}
  Use `docker login <registry-url>`. Credentials stored in `~/.docker/config.json`. For CI/CD, use credential helpers: `docker-credential-ecr-login` (AWS), `docker-credential-gcr` (Google), `docker-credential-acr` (Azure).
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Mirror vs alternate registry — what's the difference?"}
  **Mirror**: transparently proxies Docker Hub — `docker pull nginx` uses mirror automatically. **Alternate registry**: requires full path — `docker pull ghcr.io/user/image`. Mirrors only cache Docker Hub images.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="How do I deploy my own mirror?"}
  Use official `registry:2` with `REGISTRY_PROXY_REMOTEURL=https://registry-1.docker.io`. See the **Deploy Your Own Mirror** section below.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="What is OCI distribution spec?"}
  The **Open Container Initiative (OCI)** distribution specification standardizes container image storage and distribution. All modern registries (GHCR, ECR, ACR, GAR) follow OCI spec.
  :::
::

### Master daemon.json Configuration

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```json [/etc/docker/daemon.json]
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://mirror.ccs.tencentyun.com",
    "https://hub-mirror.c.163.com",
    "https://docker.m.daocloud.io",
    "https://docker.1panel.live"
  ],
  "insecure-registries": [
    "http://192.168.1.100:5000"
  ],
  "data-root": "/var/lib/docker",
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "5"
  },
  "dns": ["8.8.8.8", "8.8.4.4"],
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 5,
  "live-restore": true,
  "userland-proxy": false,
  "default-address-pools": [
    {"base": "172.17.0.0/16", "size": 24}
  ]
}
```

#code
```bash
cat /etc/docker/daemon.json
```
::

---

## 1. Ubuntu :badge[Debian-Based] :badge[22.04 / 24.04]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::steps{level="4"}

  #### Identify your system

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ cat /etc/os-release | head -5
  NAME="Ubuntu"
  VERSION="24.04.2 LTS (Noble Numbat)"
  ID=ubuntu
  ID_LIKE=debian
  VERSION_ID="24.04"

  $ uname -r
  6.8.0-60-generic

  $ arch
  x86_64
  ```

  #code
  ```bash
  cat /etc/os-release | head -5
  uname -r
  arch
  ```
  ::

  #### Remove conflicting packages

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ for pkg in docker.io docker-doc docker-compose docker-compose-v2 \
      podman-docker containerd runc; do
      sudo apt-get remove -y $pkg 2>/dev/null
    done
  Reading package lists... Done
  Package 'docker.io' is not installed, so not removed.
  Package 'containerd' is not installed, so not removed.
  ```

  #code
  ```bash
  for pkg in docker.io docker-doc docker-compose docker-compose-v2 \
    podman-docker containerd runc; do
    sudo apt-get remove -y $pkg 2>/dev/null
  done
  ```
  ::

  #### Install prerequisites

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo apt-get update
  Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease
  Get:2 http://archive.ubuntu.com/ubuntu noble-updates InRelease [89.7 kB]
  Get:3 http://security.ubuntu.com/ubuntu noble-security InRelease [126 kB]
  Reading package lists... Done

  $ sudo apt-get install -y ca-certificates curl gnupg lsb-release \
      apt-transport-https software-properties-common
  Reading package lists... Done
  Setting up ca-certificates (20240203) ...
  Setting up curl (8.5.0-2ubuntu10) ...
  Setting up gnupg (2.4.4-2ubuntu17) ...
  ```

  #code
  ```bash
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl gnupg lsb-release \
    apt-transport-https software-properties-common
  ```
  ::

  #### Add Docker GPG key and APT repository

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo install -m 0755 -d /etc/apt/keyrings

  $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
      sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  $ sudo chmod a+r /etc/apt/keyrings/docker.gpg

  $ echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  $ cat /etc/apt/sources.list.d/docker.list
  deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable
  ```

  #code
  ```bash
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  ```
  ::

  #### Install Docker Engine packages

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo apt-get update
  Hit:1 https://download.docker.com/linux/ubuntu noble InRelease
  Reading package lists... Done

  $ sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
  The following NEW packages will be installed:
    containerd.io docker-buildx-plugin docker-ce docker-ce-cli
    docker-ce-rootless-extras docker-compose-plugin
  Setting up containerd.io (1.7.24-1) ...
  Setting up docker-ce-cli (5:27.5.1-1~ubuntu.24.04~noble) ...
  Setting up docker-buildx-plugin (0.21.1-1~ubuntu.24.04~noble) ...
  Setting up docker-compose-plugin (2.33.1-1~ubuntu.24.04~noble) ...
  Setting up docker-ce (5:27.5.1-1~ubuntu.24.04~noble) ...
  Created symlink /etc/systemd/system/multi-user.target.wants/docker.service
  ```

  #code
  ```bash
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  ```
  ::

  #### Post-install — add user and verify

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo usermod -aG docker $USER
  $ newgrp docker

  $ docker version
  Client: Docker Engine - Community
   Version:           27.5.1
   API version:       1.47
   Go version:        go1.22.12
   Built:             Wed Jan 19 17:20:43 2025
   OS/Arch:           linux/amd64

  Server: Docker Engine - Community
   Engine:
    Version:          27.5.1
    API version:      1.47 (minimum version 1.24)
   containerd:
    Version:          1.7.24
   runc:
    Version:          1.2.4
   docker-init:
    Version:          0.19.0

  $ docker run --rm hello-world

  Hello from Docker!
  This message shows that your installation appears to be working correctly.

  To generate this message, Docker took the following steps:
   1. The Docker client contacted the Docker daemon.
   2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
   3. The Docker daemon created a new container from that image.
   4. The Docker daemon streamed that output to the Docker client.
  ```

  #code
  ```bash
  sudo usermod -aG docker $USER
  newgrp docker
  docker version
  docker run --rm hello-world
  ```
  ::





  :::tabs-item{icon="i-lucide-settings" label="Configure Mirrors"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  # Backup existing config
  $ sudo mkdir -p /etc/docker
  $ sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak 2>/dev/null

  # Write new configuration with multiple mirrors
  $ sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": [
      "https://docker.mirrors.ustc.edu.cn",
      "https://mirror.ccs.tencentyun.com",
      "https://hub-mirror.c.163.com",
      "https://docker.mirrors.tuna.tsinghua.edu.cn",
      "https://docker.m.daocloud.io",
      "https://docker.1panel.live",
      "https://f1361db2.m.daocloud.io",
      "https://docker.mirrors.sjtug.sjtu.edu.cn",
      "https://docker.nju.edu.cn",
      "https://dockerpull.org",
      "https://docker.rainbond.cc",
      "https://docker.bfsu.edu.cn"
    ],
    "log-driver": "json-file",
    "log-opts": {
      "max-size": "20m",
      "max-file": "5"
    },
    "storage-driver": "overlay2",
    "max-concurrent-downloads": 10
  }
  EOF

  # Reload and restart
  $ sudo systemctl daemon-reload
  $ sudo systemctl restart docker

  # Verify mirrors
  $ docker info | grep -A 18 "Registry Mirrors"
   Registry Mirrors:
    https://docker.mirrors.ustc.edu.cn/
    https://mirror.ccs.tencentyun.com/
    https://hub-mirror.c.163.com/
    https://docker.mirrors.tuna.tsinghua.edu.cn/
    https://docker.m.daocloud.io/
    https://docker.1panel.live/
    https://f1361db2.m.daocloud.io/
    https://docker.mirrors.sjtug.sjtu.edu.cn/
    https://docker.nju.edu.cn/
    https://dockerpull.org/
    https://docker.rainbond.cc/
    https://docker.bfsu.edu.cn/

  # Test pull speed
  $ time docker pull nginx:alpine
  alpine: Pulling from library/nginx
  c6a83fedfae6: Pull complete
  Digest: sha256:abcdef...
  Status: Downloaded newer image for nginx:alpine
  real    0m3.421s
  ```

  #code
  ```bash
  sudo mkdir -p /etc/docker
  sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak 2>/dev/null
  sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": [
      "https://docker.mirrors.ustc.edu.cn",
      "https://mirror.ccs.tencentyun.com",
      "https://hub-mirror.c.163.com",
      "https://docker.mirrors.tuna.tsinghua.edu.cn",
      "https://docker.m.daocloud.io",
      "https://docker.1panel.live",
      "https://f1361db2.m.daocloud.io",
      "https://docker.mirrors.sjtug.sjtu.edu.cn",
      "https://docker.nju.edu.cn",
      "https://dockerpull.org",
      "https://docker.rainbond.cc",
      "https://docker.bfsu.edu.cn"
    ],
    "log-driver": "json-file",
    "log-opts": {
      "max-size": "20m",
      "max-file": "5"
    },
    "storage-driver": "overlay2",
    "max-concurrent-downloads": 10
  }
  EOF
  sudo systemctl daemon-reload
  sudo systemctl restart docker
  docker info | grep -A 18 "Registry Mirrors"
  time docker pull nginx:alpine
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-shield" label="Pentesting Setup"}

  ::warning
  For **authorized testing only**. Unauthorized access to systems is **illegal**.
  ::

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  # Create isolated pentest network
  $ docker network create --subnet=172.20.0.0/16 pentest-lab
  a7b3c4d5e6f789...

  # Pull and deploy vulnerable targets
  $ docker pull vulnerables/web-dvwa
  $ docker pull ghcr.io/juice-shop/juice-shop
  $ docker pull webgoat/webgoat
  $ docker pull kalilinux/kali-rolling

  $ docker run -d --name dvwa --network pentest-lab \
      -p 8081:80 vulnerables/web-dvwa
  $ docker run -d --name juice-shop --network pentest-lab \
      -p 3000:3000 ghcr.io/juice-shop/juice-shop
  $ docker run -d --name webgoat --network pentest-lab \
      -p 8080:8080 -p 9090:9090 webgoat/webgoat

  # Launch Kali for testing
  $ docker run -it --rm --network pentest-lab \
      --cap-add=NET_ADMIN --cap-add=NET_RAW \
      kalilinux/kali-rolling /bin/bash

  root@kali:~# apt update && apt install -y nmap nikto sqlmap
  root@kali:~# nmap -sV 172.20.0.0/16
  Starting Nmap 7.95
  Nmap scan report for dvwa.pentest-lab (172.20.0.2)
  PORT   STATE SERVICE VERSION
  80/tcp open  http    Apache httpd 2.4.25

  Nmap scan report for juice-shop.pentest-lab (172.20.0.3)
  PORT     STATE SERVICE VERSION
  3000/tcp open  http    Node.js Express framework

  # Verify all running
  $ docker ps --format "{{.Names}}: {{.Status}} → {{.Ports}}"
  dvwa: Up 3 minutes → 0.0.0.0:8081->80/tcp
  juice-shop: Up 3 minutes → 0.0.0.0:3000->3000/tcp
  webgoat: Up 2 minutes → 0.0.0.0:8080->8080/tcp, 0.0.0.0:9090->9090/tcp
  ```

  #code
  ```bash
  docker network create --subnet=172.20.0.0/16 pentest-lab
  docker pull vulnerables/web-dvwa
  docker pull ghcr.io/juice-shop/juice-shop
  docker pull webgoat/webgoat
  docker pull kalilinux/kali-rolling
  docker run -d --name dvwa --network pentest-lab -p 8081:80 vulnerables/web-dvwa
  docker run -d --name juice-shop --network pentest-lab -p 3000:3000 ghcr.io/juice-shop/juice-shop
  docker run -d --name webgoat --network pentest-lab -p 8080:8080 -p 9090:9090 webgoat/webgoat
  docker run -it --rm --network pentest-lab --cap-add=NET_ADMIN --cap-add=NET_RAW kalilinux/kali-rolling /bin/bash
  ```
  ::

  :::


## 2. CentOS / RHEL :badge[RPM-Based] :badge[Stream 9 / RHEL 9]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::steps{level="4"}

  #### Remove old packages

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo yum remove -y docker docker-client docker-client-latest \
      docker-common docker-latest docker-latest-logrotate \
      docker-logrotate docker-engine podman runc
  No Match for argument: docker
  No packages marked for removal.
  ```

  #code
  ```bash
  sudo yum remove -y docker docker-client docker-client-latest \
    docker-common docker-latest docker-latest-logrotate \
    docker-logrotate docker-engine podman runc
  ```
  ::

  #### Install prerequisites and add Docker repo

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo yum install -y yum-utils device-mapper-persistent-data lvm2
  Installed:
    yum-utils-4.3.0-13.el9.noarch
    device-mapper-persistent-data-1.0.1-3.el9.x86_64

  $ sudo yum-config-manager --add-repo \
      https://download.docker.com/linux/centos/docker-ce.repo
  Adding repo from: https://download.docker.com/linux/centos/docker-ce.repo

  $ yum repolist | grep docker
  docker-ce-stable    Docker CE Stable - x86_64
  ```

  #code
  ```bash
  sudo yum install -y yum-utils device-mapper-persistent-data lvm2
  sudo yum-config-manager --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
  yum repolist | grep docker
  ```
  ::

  #### Install Docker Engine and start service

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo yum install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
  Installed:
    docker-ce-27.5.1-1.el9.x86_64
    docker-ce-cli-27.5.1-1.el9.x86_64
    containerd.io-1.7.24-3.1.el9.x86_64
    docker-buildx-plugin-0.21.1-1.el9.x86_64
    docker-compose-plugin-2.33.1-1.el9.x86_64
  Complete!

  $ sudo systemctl start docker
  $ sudo systemctl enable docker
  Created symlink /etc/systemd/system/multi-user.target.wants/docker.service →
    /usr/lib/systemd/system/docker.service

  $ sudo usermod -aG docker $USER && newgrp docker

  $ docker run --rm hello-world
  Hello from Docker!
  ```

  #code
  ```bash
  sudo yum install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  sudo systemctl start docker
  sudo systemctl enable docker
  sudo usermod -aG docker $USER && newgrp docker
  docker run --rm hello-world
  ```
  ::



  :::tabs-item{icon="i-lucide-settings" label="Configure Mirrors"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo mkdir -p /etc/docker
  $ sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": [
      "https://mirror.ccs.tencentyun.com",
      "https://hub-mirror.c.163.com",
      "https://docker.mirrors.ustc.edu.cn",
      "https://docker.m.daocloud.io",
      "https://docker.1panel.live",
      "https://dockerpull.org"
    ],
    "storage-driver": "overlay2"
  }
  EOF

  $ sudo systemctl daemon-reload
  $ sudo systemctl restart docker

  $ docker info | grep -A 10 "Registry Mirrors"
   Registry Mirrors:
    https://mirror.ccs.tencentyun.com/
    https://hub-mirror.c.163.com/
    https://docker.mirrors.ustc.edu.cn/
    https://docker.m.daocloud.io/
    https://docker.1panel.live/
    https://dockerpull.org/
  ```

  #code
  ```bash
  sudo mkdir -p /etc/docker
  sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": [
      "https://mirror.ccs.tencentyun.com",
      "https://hub-mirror.c.163.com",
      "https://docker.mirrors.ustc.edu.cn",
      "https://docker.m.daocloud.io",
      "https://docker.1panel.live",
      "https://dockerpull.org"
    ],
    "storage-driver": "overlay2"
  }
  EOF
  sudo systemctl daemon-reload
  sudo systemctl restart docker
  docker info | grep -A 10 "Registry Mirrors"
  ```
  ::

  :::


## 3. Fedora :badge[DNF-Based] :badge[40 / 41]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo dnf remove -y docker docker-client docker-common docker-latest \
      docker-selinux docker-engine-selinux docker-engine

  $ sudo dnf -y install dnf-plugins-core
  Package dnf-plugins-core is already installed.

  $ sudo dnf-3 config-manager --add-repo \
      https://download.docker.com/linux/fedora/docker-ce.repo
  Adding repo from: https://download.docker.com/linux/fedora/docker-ce.repo

  $ sudo dnf install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
  Installed:
    docker-ce-27.5.1-1.fc41.x86_64
  Complete!

  $ sudo systemctl start docker && sudo systemctl enable docker
  $ sudo usermod -aG docker $USER && newgrp docker

  $ docker version --format '{{.Server.Version}}'
  27.5.1
  ```

  #code
  ```bash
  sudo dnf remove -y docker docker-client docker-common docker-latest \
    docker-selinux docker-engine-selinux docker-engine
  sudo dnf -y install dnf-plugins-core
  sudo dnf-3 config-manager --add-repo \
    https://download.docker.com/linux/fedora/docker-ce.repo
  sudo dnf install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  sudo systemctl start docker && sudo systemctl enable docker
  sudo usermod -aG docker $USER && newgrp docker
  docker version --format '{{.Server.Version}}'
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-settings" label="Configure Mirrors"}

  Same `daemon.json` method — identical to CentOS. See CentOS Configure Mirrors tab.

  :::
::

## 4. Debian :badge[APT-Based] :badge[12 Bookworm]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ for pkg in docker.io docker-doc docker-compose podman-docker \
      containerd runc; do
      sudo apt-get remove -y $pkg 2>/dev/null
    done

  $ sudo apt-get update
  $ sudo apt-get install -y ca-certificates curl gnupg

  $ sudo install -m 0755 -d /etc/apt/keyrings
  $ curl -fsSL https://download.docker.com/linux/debian/gpg | \
      sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  $ sudo chmod a+r /etc/apt/keyrings/docker.gpg

  $ echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

  $ sudo apt-get update
  $ sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
  Setting up docker-ce (5:27.5.1-1~debian.12~bookworm) ...

  $ sudo usermod -aG docker $USER && newgrp docker
  $ docker run --rm hello-world
  Hello from Docker!
  ```

  #code
  ```bash
  for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
    sudo apt-get remove -y $pkg 2>/dev/null
  done
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker $USER && newgrp docker
  docker run --rm hello-world
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-settings" label="Configure Mirrors"}

  Identical `daemon.json` — see Ubuntu Configure Mirrors tab.

  :::
::

## 5. Arch Linux :badge[Pacman-Based]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo pacman -Syu docker docker-compose docker-buildx
  :: Synchronizing package databases...
   core is up to date
   extra is up to date
  resolving dependencies...

  Packages (3) docker-1:27.5.1-1  docker-compose-2.33.1-1  docker-buildx-0.21.1-1
  Total Installed Size:  189.42 MiB
  :: Proceed with installation? [Y/n] Y
  (3/3) installing docker  [######################] 100%

  $ sudo systemctl start docker && sudo systemctl enable docker
  $ sudo usermod -aG docker $USER && newgrp docker

  $ docker version --format '{{.Server.Version}}'
  27.5.1
  ```

  #code
  ```bash
  sudo pacman -Syu docker docker-compose docker-buildx
  sudo systemctl start docker && sudo systemctl enable docker
  sudo usermod -aG docker $USER && newgrp docker
  docker version --format '{{.Server.Version}}'
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-settings" label="Configure Mirrors"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo mkdir -p /etc/docker
  $ sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": [
      "https://docker.mirrors.ustc.edu.cn",
      "https://hub-mirror.c.163.com",
      "https://mirror.ccs.tencentyun.com",
      "https://docker.m.daocloud.io"
    ]
  }
  EOF
  $ sudo systemctl daemon-reload && sudo systemctl restart docker

  $ docker info | grep -A 6 "Registry Mirrors"
   Registry Mirrors:
    https://docker.mirrors.ustc.edu.cn/
    https://hub-mirror.c.163.com/
    https://mirror.ccs.tencentyun.com/
    https://docker.m.daocloud.io/
  ```

  #code
  ```bash
  sudo mkdir -p /etc/docker
  sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": [
      "https://docker.mirrors.ustc.edu.cn",
      "https://hub-mirror.c.163.com",
      "https://mirror.ccs.tencentyun.com",
      "https://docker.m.daocloud.io"
    ]
  }
  EOF
  sudo systemctl daemon-reload && sudo systemctl restart docker
  docker info | grep -A 6 "Registry Mirrors"
  ```
  ::

  :::
::

## 6. Rocky Linux / AlmaLinux :badge[RHEL-Compatible] :badge[9.x]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ cat /etc/os-release | head -3
  NAME="Rocky Linux"
  VERSION="9.4 (Blue Onyx)"
  ID="rocky"

  $ sudo dnf remove -y docker docker-client docker-common podman runc

  $ sudo dnf install -y yum-utils
  $ sudo yum-config-manager --add-repo \
      https://download.docker.com/linux/centos/docker-ce.repo
  Adding repo from: https://download.docker.com/linux/centos/docker-ce.repo

  $ sudo dnf install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin
  Installed:
    docker-ce-27.5.1-1.el9.x86_64
  Complete!

  $ sudo systemctl start docker && sudo systemctl enable docker
  $ sudo usermod -aG docker $USER && newgrp docker

  $ docker run --rm hello-world
  Hello from Docker!
  ```

  #code
  ```bash
  sudo dnf remove -y docker docker-client docker-common podman runc
  sudo dnf install -y yum-utils
  sudo yum-config-manager --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo
  sudo dnf install -y docker-ce docker-ce-cli containerd.io \
    docker-buildx-plugin docker-compose-plugin
  sudo systemctl start docker && sudo systemctl enable docker
  sudo usermod -aG docker $USER && newgrp docker
  docker run --rm hello-world
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-settings" label="Configure Mirrors"}

  Identical `daemon.json` — same as CentOS.

  :::
::

## 7. openSUSE :badge[Zypper-Based] :badge[Leap / Tumbleweed]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install & Configure"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ sudo zypper install -y docker docker-compose docker-buildx
  (1/3) Installing: docker-27.5.1-1.x86_64 ................... [done]
  (2/3) Installing: docker-compose-2.33.1-1.x86_64 ........... [done]
  (3/3) Installing: docker-buildx-0.21.1-1.x86_64 ............ [done]

  $ sudo systemctl start docker && sudo systemctl enable docker
  $ sudo usermod -aG docker $USER && newgrp docker

  $ docker version --format '{{.Server.Version}}'
  27.5.1
  ```

  #code
  ```bash
  sudo zypper install -y docker docker-compose docker-buildx
  sudo systemctl start docker && sudo systemctl enable docker
  sudo usermod -aG docker $USER && newgrp docker
  docker version --format '{{.Server.Version}}'
  ```
  ::

  :::
::

## 8. Kali Linux :badge[Pentesting] :badge[Debian-Based]

::tabs
  :::tabs-item{icon="i-lucide-terminal" label="Install Docker"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ cat /etc/os-release | head -3
  PRETTY_NAME="Kali GNU/Linux Rolling"
  NAME="Kali GNU/Linux"
  VERSION_ID="2025.1"

  # Method 1: Quick install from Kali repos
  $ sudo apt-get update
  $ sudo apt-get install -y docker.io docker-compose-v2

  # Method 2: Install Docker CE for latest version
  $ curl -fsSL https://download.docker.com/linux/debian/gpg | \
      sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  $ echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/debian bookworm stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  $ sudo apt-get update
  $ sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
      docker-buildx-plugin docker-compose-plugin

  $ sudo systemctl start docker && sudo systemctl enable docker
  $ sudo usermod -aG docker $USER && newgrp docker
  ```

  #code
  ```bash
  sudo apt-get update
  sudo apt-get install -y docker.io docker-compose-v2
  sudo systemctl start docker && sudo systemctl enable docker
  sudo usermod -aG docker $USER && newgrp docker
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-shield" label="Full Pentest Lab"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  # Create isolated lab network
  $ docker network create --subnet=172.20.0.0/16 pentest-lab
  e4f5a6b7c8d9...

  # Deploy ALL vulnerable targets
  $ docker run -d --name dvwa --network pentest-lab -p 8081:80 \
      vulnerables/web-dvwa
  $ docker run -d --name juice-shop --network pentest-lab -p 3000:3000 \
      ghcr.io/juice-shop/juice-shop
  $ docker run -d --name webgoat --network pentest-lab -p 8080:8080 \
      webgoat/webgoat
  $ docker run -d --name mutillidae --network pentest-lab -p 8082:80 \
      citizenstig/nowasp
  $ docker run -d --name hackazon --network pentest-lab -p 8083:80 \
      mutzel/all-in-one-hackazon
  $ docker run -d --name bwapp --network pentest-lab -p 8084:80 \
      raesene/bwapp

  # Deploy scanning tools
  $ docker run -d --name openvas --network pentest-lab \
      -p 9392:9392 immauss/openvas

  # Verify entire lab
  $ docker ps --format "{{.Names}} → {{.Status}} → {{.Ports}}"
  dvwa → Up 5 minutes → 0.0.0.0:8081->80/tcp
  juice-shop → Up 5 minutes → 0.0.0.0:3000->3000/tcp
  webgoat → Up 4 minutes → 0.0.0.0:8080->8080/tcp
  mutillidae → Up 4 minutes → 0.0.0.0:8082->80/tcp
  hackazon → Up 3 minutes → 0.0.0.0:8083->80/tcp
  bwapp → Up 3 minutes → 0.0.0.0:8084->80/tcp
  openvas → Up 2 minutes → 0.0.0.0:9392->9392/tcp

  # Launch Kali attacker container
  $ docker run -it --rm --network pentest-lab \
      --cap-add=NET_ADMIN --cap-add=NET_RAW \
      --name attacker kalilinux/kali-rolling /bin/bash

  root@attacker:~# apt update && apt install -y \
      nmap nikto sqlmap dirb gobuster hydra john hashcat \
      metasploit-framework exploitdb
  root@attacker:~# nmap -sV --script=vuln 172.20.0.0/16
  ```

  #code
  ```bash
  docker network create --subnet=172.20.0.0/16 pentest-lab
  docker run -d --name dvwa --network pentest-lab -p 8081:80 vulnerables/web-dvwa
  docker run -d --name juice-shop --network pentest-lab -p 3000:3000 ghcr.io/juice-shop/juice-shop
  docker run -d --name webgoat --network pentest-lab -p 8080:8080 webgoat/webgoat
  docker run -d --name mutillidae --network pentest-lab -p 8082:80 citizenstig/nowasp
  docker run -d --name hackazon --network pentest-lab -p 8083:80 mutzel/all-in-one-hackazon
  docker run -d --name bwapp --network pentest-lab -p 8084:80 raesene/bwapp
  docker run -d --name openvas --network pentest-lab -p 9392:9392 immauss/openvas
  docker run -it --rm --network pentest-lab --cap-add=NET_ADMIN --cap-add=NET_RAW kalilinux/kali-rolling /bin/bash
  ```
  ::

  :::
::

---

## Region-Specific daemon.json Templates

::code-tree{default-value="china-full.json"}

```json [china-full.json]
{
  "registry-mirrors": [
    "https://registry.cn-hangzhou.aliyuncs.com",
    "https://mirror.ccs.tencentyun.com",
    "https://hub-mirror.c.163.com",
    "https://docker.mirrors.ustc.edu.cn",
    "https://docker.mirrors.tuna.tsinghua.edu.cn",
    "https://docker.mirrors.sjtug.sjtu.edu.cn",
    "https://docker.nju.edu.cn",
    "https://docker.bfsu.edu.cn",
    "https://docker.m.daocloud.io",
    "https://f1361db2.m.daocloud.io",
    "https://docker.1panel.live",
    "https://dockerpull.org",
    "https://docker.rainbond.cc",
    "https://atomhub.openatom.cn",
    "https://05f073ad3c0010ea0f4bc00b7105ec20.mirror.swr.myhuaweicloud.com",
    "https://mirror.baidubce.com",
    "https://mirror.volces.com",
    "https://docker.geekery.cn"
  ],
  "dns": ["223.5.5.5", "114.114.114.114"],
  "storage-driver": "overlay2",
  "max-concurrent-downloads": 10,
  "live-restore": true
}
```

```json [china-alibaba.json]
{
  "registry-mirrors": [
    "https://registry.cn-hangzhou.aliyuncs.com",
    "https://registry.cn-shanghai.aliyuncs.com",
    "https://registry.cn-beijing.aliyuncs.com",
    "https://registry.cn-shenzhen.aliyuncs.com"
  ],
  "dns": ["100.100.2.136", "100.100.2.138"],
  "storage-driver": "overlay2"
}
```

```json [china-tencent.json]
{
  "registry-mirrors": [
    "https://mirror.ccs.tencentyun.com"
  ],
  "dns": ["183.60.83.19", "183.60.82.98"],
  "storage-driver": "overlay2"
}
```

```json [china-huawei.json]
{
  "registry-mirrors": [
    "https://05f073ad3c0010ea0f4bc00b7105ec20.mirror.swr.myhuaweicloud.com"
  ],
  "storage-driver": "overlay2"
}
```

```json [korea.json]
{
  "registry-mirrors": [
    "https://mirror.kakao.com"
  ],
  "dns": ["168.126.63.1", "168.126.63.2"],
  "storage-driver": "overlay2"
}
```

```json [iran.json]
{
  "registry-mirrors": [
    "https://docker.arvancloud.ir",
    "https://registry.arvandocker.ir"
  ],
  "dns": ["178.22.122.100", "185.51.200.2"],
  "storage-driver": "overlay2"
}
```

```json [russia.json]
{
  "registry-mirrors": [
    "https://cr.yandex/mirror"
  ],
  "dns": ["77.88.8.8", "77.88.8.1"],
  "storage-driver": "overlay2"
}
```

```json [europe.json]
{
  "registry-mirrors": [],
  "dns": ["1.1.1.1", "8.8.8.8"],
  "storage-driver": "overlay2",
  "max-concurrent-downloads": 10,
  "live-restore": true
}
```

```json [usa.json]
{
  "registry-mirrors": [],
  "dns": ["8.8.8.8", "8.8.4.4"],
  "storage-driver": "overlay2",
  "max-concurrent-downloads": 10,
  "live-restore": true,
  "default-address-pools": [
    {"base": "172.17.0.0/16", "size": 24}
  ]
}
```

```json [pentesting-lab.json]
{
  "registry-mirrors": [
    "https://mirror.ccs.tencentyun.com",
    "https://hub-mirror.c.163.com",
    "https://docker.mirrors.ustc.edu.cn"
  ],
  "insecure-registries": [
    "http://192.168.0.0/16:5000",
    "http://10.0.0.0/8:5000",
    "http://172.16.0.0/12:5000"
  ],
  "data-root": "/opt/docker-pentest",
  "dns": ["8.8.8.8", "1.1.1.1"],
  "max-concurrent-downloads": 15,
  "iptables": true,
  "ip-forward": true,
  "userland-proxy": false,
  "live-restore": true
}
```

```json [production-hardened.json]
{
  "registry-mirrors": [],
  "storage-driver": "overlay2",
  "live-restore": true,
  "userland-proxy": false,
  "no-new-privileges": true,
  "icc": false,
  "iptables": true,
  "ip-forward": true,
  "max-concurrent-downloads": 10,
  "default-ulimits": {
    "nofile": {"Name": "nofile", "Hard": 65536, "Soft": 32768}
  },
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "5"},
  "seccomp-profile": "/etc/docker/seccomp/default.json"
}
```

```json [air-gapped.json]
{
  "registry-mirrors": [
    "https://local-mirror.internal:5000"
  ],
  "insecure-registries": [
    "local-mirror.internal:5000"
  ],
  "dns": ["10.0.0.1"],
  "storage-driver": "overlay2",
  "live-restore": true
}
```
::

---

## Pentesting Docker Images — Complete Collection

::caution
Use these images **only** in authorized lab environments. Running offensive tools without permission is **illegal** under computer crime laws worldwide.
::

::tabs
  :::tabs-item{icon="i-lucide-shield" label="Offensive OS & Tools"}

  ::card-group
    ::card
    ---
    title: Kali Linux Rolling
    icon: i-lucide-skull
    to: https://hub.docker.com/r/kalilinux/kali-rolling
    target: _blank
    ---
    `docker pull kalilinux/kali-rolling`

    Full Kali Linux rolling release. ~127MB base, install tools with `apt`.
    ::

    ::card
    ---
    title: Parrot Security
    icon: i-lucide-shield
    to: https://hub.docker.com/r/parrotsec/security
    target: _blank
    ---
    `docker pull parrotsec/security`

    Parrot Security OS with pre-installed tools. ~5.2GB.
    ::

    ::card
    ---
    title: BlackArch Linux
    icon: i-lucide-terminal
    to: https://hub.docker.com/r/blackarchlinux/blackarch
    target: _blank
    ---
    `docker pull blackarchlinux/blackarch`

    BlackArch with 2800+ pentesting tools. ~15GB.
    ::

    ::card
    ---
    title: Metasploit Framework
    icon: i-lucide-swords
    to: https://hub.docker.com/r/metasploitframework/metasploit-framework
    target: _blank
    ---
    `docker pull metasploitframework/metasploit-framework`

    Official Metasploit container. ~2.5GB.
    ::

    ::card
    ---
    title: REMnux
    icon: i-lucide-bug
    to: https://hub.docker.com/r/remnux/remnux-distro
    target: _blank
    ---
    `docker pull remnux/remnux-distro`

    Malware analysis Linux toolkit. ~5GB.
    ::

    ::card
    ---
    title: OWASP ZAP
    icon: i-lucide-scan
    to: https://hub.docker.com/r/owasp/zap2docker-stable
    target: _blank
    ---
    `docker pull owasp/zap2docker-stable`

    OWASP Zed Attack Proxy. ~1.5GB.
    ::
  ::

  :::

  :::tabs-item{icon="i-lucide-scan" label="Scanners"}

  ::card-group
    ::card
    ---
    title: Nmap
    icon: i-lucide-radar
    to: https://hub.docker.com/r/instrumentisto/nmap
    target: _blank
    ---
    `docker pull instrumentisto/nmap`

    Network mapper and port scanner.
    ::

    ::card
    ---
    title: RustScan
    icon: i-lucide-zap
    to: https://hub.docker.com/r/rustscan/rustscan
    target: _blank
    ---
    `docker pull rustscan/rustscan`

    Modern fast port scanner in Rust. Scans all 65535 ports in seconds.
    ::

    ::card
    ---
    title: Nuclei
    icon: i-lucide-atom
    to: https://hub.docker.com/r/projectdiscovery/nuclei
    target: _blank
    ---
    `docker pull projectdiscovery/nuclei`

    Template-based vulnerability scanner by ProjectDiscovery.
    ::

    ::card
    ---
    title: Subfinder
    icon: i-lucide-search
    to: https://hub.docker.com/r/projectdiscovery/subfinder
    target: _blank
    ---
    `docker pull projectdiscovery/subfinder`

    Subdomain discovery tool.
    ::

    ::card
    ---
    title: httpx
    icon: i-lucide-globe
    to: https://hub.docker.com/r/projectdiscovery/httpx
    target: _blank
    ---
    `docker pull projectdiscovery/httpx`

    HTTP toolkit for probing and fingerprinting.
    ::

    ::card
    ---
    title: Katana
    icon: i-lucide-sword
    to: https://hub.docker.com/r/projectdiscovery/katana
    target: _blank
    ---
    `docker pull projectdiscovery/katana`

    Next-gen web crawler by ProjectDiscovery.
    ::

    ::card
    ---
    title: WPScan
    icon: i-lucide-shield-alert
    to: https://hub.docker.com/r/wpscanteam/wpscan
    target: _blank
    ---
    `docker pull wpscanteam/wpscan`

    WordPress vulnerability scanner.
    ::

    ::card
    ---
    title: Trivy
    icon: i-lucide-shield-check
    to: https://hub.docker.com/r/aquasec/trivy
    target: _blank
    ---
    `docker pull aquasec/trivy`

    Container and IaC vulnerability scanner by Aqua Security.
    ::

    ::card
    ---
    title: Grype
    icon: i-lucide-shield-check
    to: https://hub.docker.com/r/anchore/grype
    target: _blank
    ---
    `docker pull anchore/grype`

    Container vulnerability scanner by Anchore.
    ::

    ::card
    ---
    title: testssl.sh
    icon: i-lucide-lock
    to: https://hub.docker.com/r/drwetter/testssl.sh
    target: _blank
    ---
    `docker pull drwetter/testssl.sh`

    SSL/TLS testing tool.
    ::

    ::card
    ---
    title: Dockle
    icon: i-lucide-container
    to: https://hub.docker.com/r/goodwithtech/dockle
    target: _blank
    ---
    `docker pull goodwithtech/dockle`

    Container image linter for security best practices.
    ::

    ::card
    ---
    title: OpenVAS
    icon: i-lucide-scan
    to: https://hub.docker.com/r/immauss/openvas
    target: _blank
    ---
    `docker pull immauss/openvas`

    OpenVAS all-in-one vulnerability scanner. ~3GB.
    ::
  ::

  :::

  :::tabs-item{icon="i-lucide-target" label="Vulnerable Targets"}

  ::card-group
    ::card
    ---
    title: DVWA
    icon: i-lucide-target
    to: https://hub.docker.com/r/vulnerables/web-dvwa
    target: _blank
    ---
    `docker pull vulnerables/web-dvwa`

    Damn Vulnerable Web Application. Classic for learning web exploits.
    ::

    ::card
    ---
    title: OWASP Juice Shop
    icon: i-lucide-cup-soda
    to: https://github.com/juice-shop/juice-shop
    target: _blank
    ---
    `docker pull ghcr.io/juice-shop/juice-shop`

    Modern insecure web app for security training. 100+ challenges.
    ::

    ::card
    ---
    title: WebGoat
    icon: i-lucide-graduation-cap
    to: https://hub.docker.com/r/webgoat/webgoat
    target: _blank
    ---
    `docker pull webgoat/webgoat`

    OWASP WebGoat — deliberately insecure Java web app.
    ::

    ::card
    ---
    title: Mutillidae II
    icon: i-lucide-bug
    to: https://hub.docker.com/r/citizenstig/nowasp
    target: _blank
    ---
    `docker pull citizenstig/nowasp`

    OWASP Mutillidae II — 40+ vulnerabilities for OWASP Top 10.
    ::

    ::card
    ---
    title: bWAPP
    icon: i-lucide-bug
    to: https://hub.docker.com/r/raesene/bwapp
    target: _blank
    ---
    `docker pull raesene/bwapp`

    Buggy Web Application — 100+ web vulnerabilities.
    ::

    ::card
    ---
    title: Hackazon
    icon: i-lucide-shopping-cart
    to: https://hub.docker.com/r/mutzel/all-in-one-hackazon
    target: _blank
    ---
    `docker pull mutzel/all-in-one-hackazon`

    Vulnerable e-commerce site for realistic testing.
    ::

    ::card
    ---
    title: XVWA
    icon: i-lucide-alert-triangle
    to: https://hub.docker.com/r/tuxotron/xvwa
    target: _blank
    ---
    `docker pull tuxotron/xvwa`

    Xtreme Vulnerable Web Application.
    ::

    ::card
    ---
    title: DVNA
    icon: i-lucide-hexagon
    to: https://hub.docker.com/r/appsecco/dvna
    target: _blank
    ---
    `docker pull appsecco/dvna`

    Damn Vulnerable Node Application.
    ::

    ::card
    ---
    title: PyGoat
    icon: i-lucide-terminal
    to: https://hub.docker.com/r/pygoat/pygoat
    target: _blank
    ---
    `docker pull pygoat/pygoat`

    OWASP PyGoat — Python-based vulnerable app.
    ::

    ::card
    ---
    title: Damn Vulnerable WordPress
    icon: i-lucide-file-text
    to: https://hub.docker.com/r/infoslack/dvwp
    target: _blank
    ---
    `docker pull infoslack/dvwp`

    WordPress with known vulnerable plugins.
    ::

    ::card
    ---
    title: Security Shepherd
    icon: i-lucide-shield
    to: https://hub.docker.com/r/ismisepaul/securityshepherd
    target: _blank
    ---
    `docker pull ismisepaul/securityshepherd`

    OWASP Security Shepherd — gamified security training.
    ::

    ::card
    ---
    title: Vulhub
    icon: i-lucide-database
    to: https://github.com/vulhub/vulhub
    target: _blank
    ---
    `git clone https://github.com/vulhub/vulhub.git`

    200+ pre-built vulnerable environments via docker-compose.
    ::
  ::

  :::

  :::tabs-item{icon="i-lucide-network" label="Network & OSINT"}

  ::card-group
    ::card
    ---
    title: Netshoot
    icon: i-lucide-network
    to: https://hub.docker.com/r/nicolaka/netshoot
    target: _blank
    ---
    `docker pull nicolaka/netshoot`

    Network troubleshooting Swiss Army knife.
    ::

    ::card
    ---
    title: SpiderFoot
    icon: i-lucide-spider
    to: https://hub.docker.com/r/smicallef/spiderfoot
    target: _blank
    ---
    `docker pull smicallef/spiderfoot`

    OSINT automation tool with 200+ modules.
    ::

    ::card
    ---
    title: Sherlock
    icon: i-lucide-search
    to: https://hub.docker.com/r/sherlock-project/sherlock
    target: _blank
    ---
    `docker pull sherlock-project/sherlock`

    Hunt usernames across 400+ social networks.
    ::

    ::card
    ---
    title: OWASP Amass
    icon: i-lucide-globe
    to: https://github.com/owasp-amass/amass
    target: _blank
    ---
    `docker pull ghcr.io/owasp-amass/amass`

    Attack surface mapping and subdomain enumeration.
    ::

    ::card
    ---
    title: Bettercap
    icon: i-lucide-wifi
    to: https://hub.docker.com/r/bettercap/bettercap
    target: _blank
    ---
    `docker pull bettercap/bettercap`

    Swiss Army knife for network attacks and monitoring.
    ::

    ::card
    ---
    title: MobSF
    icon: i-lucide-smartphone
    to: https://hub.docker.com/r/opensecurity/mobile-security-framework-mobsf
    target: _blank
    ---
    `docker pull opensecurity/mobile-security-framework-mobsf`

    Mobile Security Framework — Android/iOS analysis.
    ::
  ::

  :::
::

---

## Quick Pull Commands — All Major Registries

::code-group

```bash [Docker Hub]
docker pull nginx:latest
docker pull nginx:1.27-alpine
docker pull alpine:3.20
docker pull ubuntu:24.04
docker pull debian:bookworm-slim
docker pull node:22-alpine
docker pull python:3.13-slim
docker pull golang:1.23-alpine
docker pull rust:1.82-slim
docker pull redis:7-alpine
docker pull postgres:17-alpine
docker pull mysql:8.4
docker pull mongo:8.0
docker pull httpd:2.4-alpine
docker pull traefik:v3.3
docker pull grafana/grafana:latest
docker pull prom/prometheus:latest
docker pull portainer/portainer-ce:latest
```

```bash [GHCR (GitHub)]
docker pull ghcr.io/juice-shop/juice-shop:latest
docker pull ghcr.io/linuxserver/wireguard:latest
docker pull ghcr.io/linuxserver/code-server:latest
docker pull ghcr.io/home-assistant/home-assistant:stable
docker pull ghcr.io/open-webui/open-webui:main
docker pull ghcr.io/owasp-amass/amass:latest
docker pull ghcr.io/astral-sh/uv:latest
docker pull ghcr.io/containrrr/watchtower:latest
docker pull ghcr.io/dani-garcia/vaultwarden:latest
```

```bash [Google GCR / Artifact Registry]
docker pull gcr.io/distroless/static-debian12:latest
docker pull gcr.io/distroless/base-debian12:latest
docker pull gcr.io/distroless/java21-debian12:latest
docker pull gcr.io/distroless/python3-debian12:latest
docker pull gcr.io/distroless/nodejs22-debian12:latest
docker pull gcr.io/google-containers/pause:3.10
docker pull gcr.io/kaniko-project/executor:latest
docker pull us-docker.pkg.dev/cloudrun/container/hello:latest
```

```bash [AWS ECR Public]
docker pull public.ecr.aws/nginx/nginx:latest
docker pull public.ecr.aws/docker/library/alpine:latest
docker pull public.ecr.aws/docker/library/ubuntu:24.04
docker pull public.ecr.aws/amazonlinux/amazonlinux:2023
docker pull public.ecr.aws/aws-cli/aws-cli:latest
docker pull public.ecr.aws/lambda/python:3.13
docker pull public.ecr.aws/lambda/nodejs:22
docker pull public.ecr.aws/bitnami/nginx:latest
```

```bash [Quay.io (Red Hat)]
docker pull quay.io/centos/centos:stream9
docker pull quay.io/fedora/fedora:41
docker pull quay.io/podman/stable:latest
docker pull quay.io/prometheus/prometheus:latest
docker pull quay.io/prometheus/node-exporter:latest
docker pull quay.io/coreos/etcd:latest
docker pull quay.io/argoproj/argocd:latest
docker pull quay.io/jetstack/cert-manager-controller:latest
docker pull quay.io/minio/minio:latest
```

```bash [Azure MCR (Microsoft)]
docker pull mcr.microsoft.com/dotnet/aspnet:8.0
docker pull mcr.microsoft.com/dotnet/sdk:8.0
docker pull mcr.microsoft.com/mssql/server:2022-latest
docker pull mcr.microsoft.com/azure-cli:latest
docker pull mcr.microsoft.com/powershell:latest
docker pull mcr.microsoft.com/playwright:latest
docker pull mcr.microsoft.com/devcontainers/python:3.13
docker pull mcr.microsoft.com/vscode/devcontainers/base:ubuntu
```

```bash [Alibaba China]
docker pull registry.cn-hangzhou.aliyuncs.com/library/nginx:latest
docker pull registry.cn-hangzhou.aliyuncs.com/library/alpine:latest
docker pull registry.cn-hangzhou.aliyuncs.com/library/ubuntu:24.04
docker pull registry.cn-hangzhou.aliyuncs.com/library/python:3.13
docker pull registry.cn-hangzhou.aliyuncs.com/library/node:22
docker pull registry.cn-hangzhou.aliyuncs.com/library/redis:7
docker pull registry.cn-hangzhou.aliyuncs.com/library/mysql:8.4
docker pull registry.cn-hangzhou.aliyuncs.com/library/postgres:17
```

```bash [Yandex Russia]
docker pull cr.yandex/mirror/nginx:latest
docker pull cr.yandex/mirror/ubuntu:24.04
docker pull cr.yandex/mirror/alpine:3.20
docker pull cr.yandex/mirror/python:3.13
docker pull cr.yandex/mirror/redis:7
docker pull cr.yandex/mirror/postgres:17
```

```bash [Oracle Cloud]
docker pull container-registry.oracle.com/database/express:latest
docker pull container-registry.oracle.com/java/jdk:21
docker pull container-registry.oracle.com/os/oraclelinux:9
docker pull container-registry.oracle.com/mysql/mysql-server:latest
```

```bash [GitLab Registry]
docker pull registry.gitlab.com/gitlab-org/gitlab-runner:latest
docker pull registry.gitlab.com/gitlab-org/gitlab-ce:latest
docker pull registry.gitlab.com/pages/hugo:latest
```

::

---

## Deploy Your Own Registry Mirror

::tip{to="https://docs.docker.com/docker-hub/mirror/"}
Running a local pull-through cache eliminates internet dependency and dramatically speeds up pulls for teams and CI/CD.
::

::tabs
  :::tabs-item{icon="i-lucide-server" label="Pull-Through Cache"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  # Create directories
  $ sudo mkdir -p /opt/registry/{data,config,certs}

  # Create pull-through cache config
  $ sudo tee /opt/registry/config/config.yml <<'EOF'
  version: 0.1
  log:
    fields:
      service: registry
  storage:
    cache:
      blobdescriptor: inmemory
    filesystem:
      rootdirectory: /var/lib/registry
    delete:
      enabled: true
  http:
    addr: :5000
    headers:
      X-Content-Type-Options: [nosniff]
  proxy:
    remoteurl: https://registry-1.docker.io
  EOF

  # Run the mirror
  $ docker run -d --name registry-mirror \
      --restart=always \
      -p 5000:5000 \
      -v /opt/registry/data:/var/lib/registry \
      -v /opt/registry/config/config.yml:/etc/docker/registry/config.yml \
      registry:2
  d1e2f3a4b5c6...

  # Verify
  $ curl -s http://localhost:5000/v2/ | jq .
  {}

  $ docker logs registry-mirror | head -3
  time="2025-06-01T10:00:00Z" level=info msg="listening on [::]:5000"
  time="2025-06-01T10:00:00Z" level=info msg="Starting upload purge in 15m0s"

  # Configure clients to use this mirror
  $ sudo tee /etc/docker/daemon.json <<'EOF'
  {
    "registry-mirrors": ["http://your-server-ip:5000"]
  }
  EOF
  $ sudo systemctl daemon-reload && sudo systemctl restart docker
  ```

  #code
  ```bash
  sudo mkdir -p /opt/registry/{data,config,certs}
  sudo tee /opt/registry/config/config.yml <<'EOF'
  version: 0.1
  log:
    fields:
      service: registry
  storage:
    cache:
      blobdescriptor: inmemory
    filesystem:
      rootdirectory: /var/lib/registry
    delete:
      enabled: true
  http:
    addr: :5000
    headers:
      X-Content-Type-Options: [nosniff]
  proxy:
    remoteurl: https://registry-1.docker.io
  EOF
  docker run -d --name registry-mirror --restart=always \
    -p 5000:5000 \
    -v /opt/registry/data:/var/lib/registry \
    -v /opt/registry/config/config.yml:/etc/docker/registry/config.yml \
    registry:2
  curl -s http://localhost:5000/v2/ | jq .
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-lock" label="With TLS"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  # Generate self-signed cert
  $ openssl req -newkey rsa:4096 -nodes \
      -keyout /opt/registry/certs/domain.key \
      -x509 -days 365 \
      -out /opt/registry/certs/domain.crt \
      -subj "/CN=registry.local" \
      -addext "subjectAltName=DNS:registry.local,IP:192.168.1.100"

  # Run with TLS
  $ docker run -d --name registry-tls \
      --restart=always -p 443:5000 \
      -v /opt/registry/data:/var/lib/registry \
      -v /opt/registry/certs:/certs \
      -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
      -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
      registry:2

  # Trust cert on Ubuntu/Debian
  $ sudo cp /opt/registry/certs/domain.crt \
      /usr/local/share/ca-certificates/registry.local.crt
  $ sudo update-ca-certificates

  # Trust cert on CentOS/RHEL
  $ sudo cp /opt/registry/certs/domain.crt \
      /etc/pki/ca-trust/source/anchors/registry.local.crt
  $ sudo update-ca-trust

  $ sudo systemctl restart docker
  ```

  #code
  ```bash
  openssl req -newkey rsa:4096 -nodes \
    -keyout /opt/registry/certs/domain.key \
    -x509 -days 365 \
    -out /opt/registry/certs/domain.crt \
    -subj "/CN=registry.local" \
    -addext "subjectAltName=DNS:registry.local,IP:192.168.1.100"
  docker run -d --name registry-tls --restart=always -p 443:5000 \
    -v /opt/registry/data:/var/lib/registry \
    -v /opt/registry/certs:/certs \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt \
    -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key \
    registry:2
  ```
  ::

  :::

  :::tabs-item{icon="i-lucide-database" label="Harbor Enterprise"}

  ::code-preview
  ---
  class: "[&>div]:*:my-0 [&>div]:*:w-full"
  ---

  ```bash
  $ curl -sL https://github.com/goharbor/harbor/releases/download/v2.11.2/harbor-online-installer-v2.11.2.tgz | tar xz
  $ cd harbor
  $ cp harbor.yml.tmpl harbor.yml
  $ vim harbor.yml   # Set hostname, https, admin password

  $ sudo ./install.sh --with-trivy
  [Step 0]: checking if docker is installed ...
  [Step 1]: checking docker-compose is installed ...
  [Step 2]: loading Harbor images ...
  [Step 3]: preparing environment ...
  [Step 4]: preparing harbor configs ...
  [Step 5]: starting Harbor ...
  ✔ ----Harbor has been installed and started successfully.----

  $ docker login harbor.example.com
  Username: admin
  Password: ********
  Login Succeeded

  $ docker tag nginx:latest harbor.example.com/library/nginx:latest
  $ docker push harbor.example.com/library/nginx:latest
  latest: digest: sha256:abc... size: 1234
  ```

  #code
  ```bash
  curl -sL https://github.com/goharbor/harbor/releases/download/v2.11.2/harbor-online-installer-v2.11.2.tgz | tar xz
  cd harbor && cp harbor.yml.tmpl harbor.yml
  vim harbor.yml
  sudo ./install.sh --with-trivy
  docker login harbor.example.com
  docker tag nginx:latest harbor.example.com/library/nginx:latest
  docker push harbor.example.com/library/nginx:latest
  ```
  ::

  :::
::

---

## Registry Reconnaissance (Pentesting)

::warning
Only perform reconnaissance against **your own infrastructure** or with **explicit written authorization**. Unauthorized access violates computer crime laws.
::

::collapsible

::code-preview
---
class: "[&>div]:*:my-0 [&>div]:*:w-full"
---

```bash
# ============================================
# REGISTRY API ENUMERATION
# ============================================

# Check registry accessibility
$ curl -sk https://registry.example.com/v2/ | jq .
{}

# List all repositories
$ curl -sk https://registry.example.com/v2/_catalog | jq .
{
  "repositories": [
    "app/backend",
    "app/frontend",
    "internal/secrets-manager"
  ]
}

# List tags
$ curl -sk https://registry.example.com/v2/app/backend/tags/list | jq .
{
  "name": "app/backend",
  "tags": ["latest", "v1.0.0", "v1.1.0", "dev-abc123f"]
}

# Get image config (may reveal secrets!)
$ DIGEST=$(curl -sk -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    https://registry.example.com/v2/app/backend/manifests/latest | jq -r '.config.digest')
$ curl -sk https://registry.example.com/v2/app/backend/blobs/$DIGEST | jq '.config.Env'
[
  "DATABASE_URL=postgres://admin:s3cret@db:5432/prod",
  "API_KEY=sk-live-abc123456789"
]

# ============================================
# NETWORK SCANNING
# ============================================

# Scan for exposed registries
$ nmap -sV -p 5000,443,8443 --script=http-docker-registry 192.168.1.0/24
PORT     STATE SERVICE VERSION
5000/tcp open  http    Docker Registry (API: 2.0)

# Scan for exposed Docker daemon (CRITICAL!)
$ nmap -sV -p 2375,2376 192.168.1.0/24
PORT     STATE SERVICE VERSION
2375/tcp open  docker  Docker Engine API 1.47

# If Docker API is exposed (unauthenticated!)
$ curl -s http://192.168.1.50:2375/containers/json | jq '.[].Names'
["/webapp"]
["/database"]

# ============================================
# VULNERABILITY SCANNING
# ============================================

# Trivy scan
$ docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:latest
Total: 7 (HIGH: 5, CRITICAL: 2)

# Grype scan
$ docker run --rm anchore/grype nginx:latest

# Dockle best practices
$ docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    goodwithtech/dockle nginx:latest
```

#code
```bash
curl -sk https://registry.example.com/v2/ | jq .
curl -sk https://registry.example.com/v2/_catalog | jq .
nmap -sV -p 5000,443 --script=http-docker-registry 192.168.1.0/24
docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:latest
docker run --rm anchore/grype nginx:latest
```
::

::

---

## Docker Commands Master Cheatsheet

::code-collapse

```bash [docker-master-cheatsheet.sh]
#!/bin/bash
# ================================================================
# DOCKER MASTER CHEATSHEET — Registry, Images, Containers, Security
# ================================================================

# ---- AUTHENTICATION ----
docker login                                       # Docker Hub
docker login ghcr.io                               # GitHub
docker login registry.cn-hangzhou.aliyuncs.com     # Alibaba China
docker login cr.yandex                             # Yandex Russia
docker login quay.io                               # Quay / Red Hat
docker login registry.gitlab.com                   # GitLab
docker login public.ecr.aws                        # AWS ECR Public
docker login <acct>.dkr.ecr.<region>.amazonaws.com # AWS ECR Private
docker login <name>.azurecr.io                     # Azure ACR
docker login gcr.io                                # Google GCR
docker login <region>-docker.pkg.dev               # Google GAR
docker login harbor.example.com                    # Self-hosted Harbor

# ---- IMAGES ----
docker pull nginx:latest                           # Pull
docker pull --platform linux/arm64 nginx:latest    # Specific arch
docker push myregistry.com/myimage:v1              # Push
docker tag nginx:latest myregistry.com/nginx:v1    # Tag
docker images                                      # List
docker images --format "{{.Repository}}:{{.Tag}} {{.Size}}"
docker image ls --digests                          # Show digests
docker image prune -a                              # Remove unused
docker image inspect nginx:latest                  # Inspect
docker image history nginx:latest                  # Show layers
docker manifest inspect nginx:latest               # Multi-arch
docker save -o nginx.tar nginx:latest              # Export to tar
docker load -i nginx.tar                           # Import from tar

# ---- CONTAINERS ----
docker run -d --name web -p 80:80 nginx            # Run detached
docker run -it --rm alpine /bin/sh                 # Interactive
docker run --memory=512m --cpus=1.5 nginx          # Resource limits
docker exec -it web /bin/bash                      # Enter
docker logs -f --tail 100 web                      # Follow logs
docker stats                                       # Live resources
docker inspect web                                 # Details
docker cp file.txt web:/tmp/                       # Copy in
docker cp web:/var/log/nginx/access.log ./         # Copy out
docker diff web                                    # FS changes
docker top web                                     # Processes
docker update --memory=1g web                      # Update

# ---- REGISTRY INFO ----
docker info                                        # Full info
docker info | grep -A 15 "Registry Mirrors"        # Check mirrors
docker system df                                   # Disk usage
docker system prune -a --volumes                   # Full cleanup

# ---- NETWORK ----
docker network ls                                  # List
docker network create --subnet=10.10.0.0/16 lab    # Create
docker network inspect bridge                      # Inspect
docker run --network=host nginx                    # Host mode
docker run --network=none alpine                   # No network

# ---- VOLUMES ----
docker volume ls                                   # List
docker volume create mydata                        # Create
docker run -v mydata:/data nginx                   # Named volume
docker run -v $(pwd):/app nginx                    # Bind mount

# ---- BUILD ----
docker build -t myapp:v1 .                         # Build
docker build -t myapp:v1 -f Dockerfile.prod .      # Custom file
docker build --no-cache -t myapp:v1 .              # No cache
docker buildx build --platform linux/amd64,linux/arm64 -t myapp:v1 --push .

# ---- COMPOSE ----
docker compose up -d                               # Start
docker compose up -d --build                       # Rebuild
docker compose down -v                             # Stop + volumes
docker compose logs -f                             # Follow logs
docker compose ps                                  # Status
docker compose exec web /bin/bash                  # Enter service

# ---- SECURITY ----
docker run --rm -it kalilinux/kali-rolling /bin/bash
docker run --rm -it --cap-add=NET_ADMIN nicolaka/netshoot
docker run -d -p 3000:3000 ghcr.io/juice-shop/juice-shop
docker run --rm aquasec/trivy image nginx:latest
docker run --rm anchore/grype nginx:latest
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  goodwithtech/dockle nginx:latest
```

::

---

## Universal Mirror Setup — Any Linux Distro

::tip
The `daemon.json` configuration is **identical** across all Linux distributions. Only the Docker **installation** differs by distro.
::

::field-group
  ::field{name="Step 1" type="command"}
  `sudo mkdir -p /etc/docker` — Create config directory.
  ::

  ::field{name="Step 2" type="command"}
  `sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak` — Back up existing config.
  ::

  ::field{name="Step 3" type="command"}
  `sudo nano /etc/docker/daemon.json` — Edit daemon configuration.
  ::

  ::field{name="Step 4" type="json"}
  Add `"registry-mirrors": ["https://mirror-1", "https://mirror-2"]` — Multiple mirrors for failover.
  ::

  ::field{name="Step 5" type="command"}
  `sudo systemctl daemon-reload` — Reload systemd.
  ::

  ::field{name="Step 6" type="command"}
  `sudo systemctl restart docker` — Apply changes.
  ::

  ::field{name="Step 7" type="command"}
  `docker info | grep -A 15 "Registry Mirrors"` — Verify mirrors are active.
  ::

  ::field{name="Step 8" type="command"}
  `time docker pull nginx:alpine` — Test pull speed.
  ::
::

## Troubleshooting

::accordion
  :::accordion-item{icon="i-lucide-circle-help" label="Docker won't start after editing daemon.json"}
  **Cause:** Invalid JSON syntax.

  **Fix:** Validate with `python3 -m json.tool /etc/docker/daemon.json`. Fix syntax or restore backup: `sudo cp /etc/docker/daemon.json.bak /etc/docker/daemon.json`.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Mirrors not working — pulls still slow"}
  **Fix:**
  1. Restart Docker: `sudo systemctl restart docker`
  2. Verify: `docker info | grep -A 10 "Registry Mirrors"`
  3. Test mirror: `curl -s https://mirror-url/v2/ | jq .`
  4. Try different mirror from the list
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Permission denied running docker commands"}
  **Fix:** `sudo usermod -aG docker $USER && newgrp docker` — or logout and login.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Cannot connect to Docker daemon socket"}
  **Fix:** `sudo systemctl start docker && sudo systemctl status docker`. Check logs: `sudo journalctl -xeu docker.service`.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="toomanyrequests — Docker Hub rate limit"}
  **Fix:**
  1. `docker login` — authenticate for higher limits
  2. Configure registry mirrors
  3. Use alternate registries (ECR Public, GHCR, Quay)
  4. Deploy local pull-through cache
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="x509: certificate signed by unknown authority"}
  **Fix (Ubuntu):** `sudo cp ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`

  **Fix (CentOS):** `sudo cp ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust`

  Or add `"insecure-registries": ["registry:5000"]` (not recommended for production).
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="No space left on device"}
  **Fix:** `docker system df` to check, then `docker system prune -a --volumes` to clean. Change `data-root` in `daemon.json` to a larger disk.
  :::

  :::accordion-item{icon="i-lucide-circle-help" label="Conflict: container name already in use"}
  **Fix:** `docker rm -f container_name` — or use `--rm` flag for auto-cleanup.
  :::
::

::note
Regardless of your Linux distribution or world region, `/etc/docker/daemon.json` and registry mirror setup is **exactly the same**. Only Docker **installation** and **mirror URLs** differ.
::