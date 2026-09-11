#include <linux/types.h>
#include <linux/slab.h>      // kmalloc, kfree, GFP_KERNEL 用
#include <linux/string.h>    // strcpy 用
#include <linux/kernel.h>    // pr_info, pr_notice 用
#include <linux/io.h>        // virt_to_phys 用
#include <asm/sbi.h>         // sbi_ecall 用 (RISC-V固有)

/**
 * Table 100. Message Header Format 
 * ゲストとPSPファームウェア間の通信に使用されるメッセージヘッダー
 */
struct __attribute__((packed)) snp_guest_msg_hdr {
    /* 00h: メッセージ認証タグ (AEADアルゴリズムのTag) [cite: 100, 2298] */
    uint8_t authtag[32];
    /* 20h: メッセージのシーケンス番号。IVの構築に使用される [cite: 100, 2300] */
    uint64_t msg_seqno;
    /* 28h: 予約済み (127:64ビット) [cite: 100, 2300] */
    uint8_t reserved_1[8];
    /* 30h: メッセージの暗号化に使用されたAEADアルゴリズム [cite: 100, 2301, 2308] 
     * 1h: AES-256-GCM
     */
    uint8_t algo;
    /* 31h: メッセージヘッダーのバージョン。本仕様では1h [cite: 100, 2302] */
    uint8_t hdr_version;
    /* 32h: メッセージヘッダーのサイズ (バイト単位) [cite: 100, 2303] */
    uint16_t hdr_size;
    /* 34h: ペイロードのタイプ (例: 5h=MSG_REPORT_REQ) [cite: 100, 2304, 2310] */
    uint8_t msg_type;
    /* 35h: ペイロードのバージョン [cite: 100, 2305, 2310] */
    uint8_t msg_version;
    /* 36h: ペイロードのサイズ (バイト単位) [cite: 100, 2306] */
    uint16_t msg_size;
    /* 38h: 予約済み。0である必要がある [cite: 100, 2306] */
    uint32_t reserved_2;
    /* 3Ch: メッセージ保護に使用されたVMPCKのID (0-3)  */
    uint8_t msg_vmpck;
    /* 3Dh: 予約済み。0である必要がある  */
    uint8_t reserved_3;
    /* 3Eh: 予約済み。0である必要がある  */
    uint16_t reserved_4;
    /* 40h-5Fh: 予約済み。0である必要がある  */
    uint8_t reserved_5[32];
};
/*
 * ゲストがアテステーションレポートを要求するために送信するペイロード
 */
struct __attribute__((packed)) snp_msg_report_req {
    /* 00h: ゲストが指定する512ビット（64バイト）の任意データ
     * 通常はNonceや公開鍵のハッシュなどを格納し、レポートに含める
     */
    uint8_t report_data[64];
    /* 40h: レポートを要求する特権レベル (VMPL) */
    uint32_t vmpl;
    /* 44h: 署名に使用する鍵の選択 (KEY_SEL) */
    uint32_t key_sel;
    /* 48h-5Fh: 予約済み。0でクリアされている必要がある */
    uint8_t reserved[24];
};
/* アテステーションレポート要求のレスポンス本体 */
/* 本来は暗号化されているものを復号する　*/
struct __attribute__((packed)) snp_msg_report_rsp {
    uint32_t status;          /* 処理ステータス (0h: Success) [cite: 1120] */
    uint32_t report_size;     /* レポートのサイズ [cite: 1120] */
    uint8_t reserved[24];     /* [cite: 1120] */
    /* 実際のアテステーションレポート本体 (Table 23) [cite: 1120] */
    /* 約 1184バイトのバイナリデータ */
    uint8_t report[];         
};
/**
 * Table 23. ATTESTATION REPORT Structure
 * AMD SEV-SNP仕様に基づくアテステーションレポートのバイナリ構造
 * 合計サイズ: 1184バイト (4A0h) [cite: 1098, 1110]
 */
struct __attribute__((packed)) snp_attestation_report {
    /* 00h: レポートのバージョン (現行仕様では 5h)  */
    uint32_t version;
    /* 04h: ゲストのセキュリティバージョン番号 (SVN)  */
    uint32_t guest_svn;
    /* 08h: ゲストポリシー  */
    uint64_t policy;
    /* 10h: ゲストオーナー提供のファミリーID (16バイト)  */
    uint8_t family_id[16];
    /* 20h: ゲストオーナー提供のイメージID (16バイト)  */
    uint8_t image_id[16];
    /* 30h: レポートを要求したVMPLレベル (0-3 または 0xFFFFFFFF)  */
    uint32_t vmpl;
    /* 34h: 署名アルゴリズム (1h: ECDSA P-384 with SHA-384)  */
    uint32_t signature_algo;
    /* 38h: 現在のファームウェアTCBバージョン  */
    uint64_t current_tcb;
    /* 40h: プラットフォーム情報 (SMT, TSME, ALIAS_CHECK等) [cite: 1098, 1112] */
    uint64_t platform_info;

    /* 48h: 署名キー情報およびフラグ [cite: 1104]
     * bit 0: AUTHOR_KEY_EN (Author公開鍵の有無)
     * bit 1: MASK_CHIP_KEY (MaskChipKeyの値)
     * bit 4:2: SIGNING_KEY (0: VCEK, 1: VLEK, 7: None)
     */
    uint32_t flags;
    /* 4Ch: 予約済み (MBZ) [cite: 1104] */
    uint32_t reserved1;

    /* 50h: ゲスト提供の64バイトデータ (Nonce等) [cite: 1104] */
    uint8_t report_data[64];
    /* 90h: ゲスト起動時に計測されたハッシュ値 (SHA-384) [cite: 1104] */
    uint8_t measurement[48];
    /* C0h: ハイパーバイザ提供のホストデータ [cite: 1104] */
    uint8_t host_data[32];
    /* E0h: ID公開鍵のSHA-384ダイジェスト [cite: 1104] */
    uint8_t id_key_digest[48];
    /* 110h: Author公開鍵のSHA-384ダイジェスト [cite: 1104] */
    uint8_t author_key_digest[48];
    /* 140h: このゲストインスタンス固有のレポートID [cite: 1104] */
    uint8_t report_id[32];
    /* 160h: 移行エージェント (MA) のレポートID [cite: 1104] */
    uint8_t report_id_ma[32];
    /* 180h: 署名に使用されたReported TCBバージョン [cite: 1104] */
    uint64_t reported_tcb;

    /* 188h: CPU識別情報 (Family, Model, Stepping) [cite: 1104] */
    uint8_t cpuid_fam_id;
    uint8_t cpuid_mod_id;
    uint8_t cpuid_step;
    uint8_t reserved2[21]; /* 18Bh-19Fh [cite: 1104] */

    /* 1A0h: チップ固有の識別子 (MASK_CHIP_ID=0の場合のみ有効) [cite: 1104] */
    uint8_t chip_id[64];
    /* 1E0h: Committed TCBバージョン [cite: 1104] */
    uint64_t committed_tcb;

    /* 1E8h: 現在のファームウェアビルド・バージョン情報 [cite: 1104] */
    uint8_t current_build;
    uint8_t current_minor;
    uint8_t current_major;
    uint8_t reserved3;
    /* 1Ech: コミット済みのビルド・バージョン情報  */
    uint8_t committed_build;
    uint8_t committed_minor;
    uint8_t committed_major;
    uint8_t reserved4;

    /* 1F0h: ゲスト起動/インポート時のTCBバージョン  */
    uint64_t launch_tcb;
    /* 1F8h: ゲスト起動時の検証済み脆弱性対策ベクトル  */
    uint64_t launch_mit_vector;
    /* 200h: 現在の検証済み脆弱性対策ベクトル  */
    uint64_t current_mit_vector;

    /* 208h: 予約済み (MBZ)  */
    uint8_t reserved5[152];

    /* 2A0h: レポート全体 (オフセット0hから29Fh) に対する署名 
     * フォーマットは ECDSA P-384 with SHA-384 (Table 141) [cite: 2650]
     */
    uint8_t signature[512];
};

/* 構造体のサイズは合計で 96バイト (60h) になる  */
//add 
void sys_snp_guest_request(void)
{

	unsigned long req_gpa; //送信用データのGPA
	unsigned long res_gpa; //受信用データのGPA
	struct snp_guest_msg_hdr *req_header; //送信用ヘッダ
	struct snp_guest_msg_hdr *res_header; //受信用ヘッダ
	struct snp_msg_report_req *req_data; //リクエストの中身 
	struct snp_msg_report_rsp *res_data; //レスポンスの中身
	struct snp_attestation_report *report; //アテステーションレポート
	req_header = kmalloc(4096, GFP_KERNEL); //送信用データのメモリ割り当て
	res_header = kmalloc(4096, GFP_KERNEL); //受信用データのメモリ割り当て
	//ヘッダサイズ設定(96バイト)
	req_header->hdr_size = sizeof(struct snp_guest_msg_hdr);
	res_header->hdr_size = req_header->hdr_size;
	//メッセージタイプ設定(5:MSG_REPORT_REQ)
	req_header->msg_type = 5;
	//リクエストデータセット
	req_data = (struct  snp_msg_report_req *)(req_header + (unsigned long)req_header->hdr_size);
	//ノンスのコピー
	strcpy(req_data->report_data, "test");

	//GVAからGPAに変換
	req_gpa = virt_to_phys((void *)req_header);
	res_gpa = virt_to_phys((void *)res_header);
	
	pr_info("\n\ntry SNP_GUEST_REQUEST\n");
	// SNP_GUEST_REQUEST実行
	sbi_ecall(0x08000000, 0x94, req_gpa,res_gpa,0,0,0,0);
	res_data = (struct snp_msg_report_rsp *)(res_header + (unsigned long)res_header->hdr_size);
	report = (struct snp_attestation_report *)res_data->report;

	pr_notice("LD: ");
	for(int i=0; i < 48; i++){
		pr_notice("%02x",report->measurement[i]);
	}
	pr_notice("\n ");
	kfree(req_header);
	kfree(res_header);
}

