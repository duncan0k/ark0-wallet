//! Confirmations in a dialog of the operating system, outside the web view: what the web view cannot
//! answer for the user. A payment is signed, and a wallet removed without its password, only after one.
//! The wording is the core's own, in the interface's language, with the figures of the frozen plan.
use crate::sources::Flags;
use tauri::AppHandle;
#[cfg(desktop)]
use tauri::Manager;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

/// The language of a dialog: the interface's setting, or for "auto" the language the interface resolved.
pub fn locale(setting: &str, resolved: Option<&str>) -> &'static str {
    let pick = if setting == "auto" { resolved.unwrap_or("en") } else { setting };
    match pick {
        "zh-Hans" => "zh-Hans",
        "zh-Hant" => "zh-Hant",
        _ => "en",
    }
}

/// Coins from satoshis, as the interface writes them: 150000000 is "1.5".
fn coins(sats: u64) -> String {
    let fraction = format!("{:08}", sats % 100_000_000);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        (sats / 100_000_000).to_string()
    } else {
        format!("{}.{fraction}", sats / 100_000_000)
    }
}

pub struct Dialog {
    title: &'static str,
    body: String,
    ok: &'static str,
    cancel: &'static str,
}

/// The confirmation of a payment; `caution` adds that an earlier payment may have gone out after all.
pub fn payment(locale: &str, send: u64, to: &str, fee: u64, change: u64, caution: bool, sources: Flags) -> Dialog {
    let (send, fee, change_text) = (coins(send), coins(fee), coins(change));
    match locale {
        "zh-Hans" => Dialog {
            title: "确认转出",
            body: format!(
                "转出 {send} 测试币\n收款地址：\n{to}\n\n手续费 {fee} 测试币{}。\n\n{}{}{}确认后立即签名并发出，无法撤回。",
                if change > 0 { format!("，找零 {change_text} 测试币回到你的地址") } else { String::new() },
                if caution { "注意：之前有转账没能确认发出，它可能已经发出；这一笔会在它之外另行支付。\n\n" } else { "" },
                if sources.one_source { "注意：这次只有一个节点回应，没能用另一个节点核对。\n\n" } else { "" },
                if sources.disagree { "注意：两个节点的回答不一致。\n\n" } else { "" }
            ),
            ok: "签名并发出",
            cancel: "取消",
        },
        "zh-Hant" => Dialog {
            title: "確認轉出",
            body: format!(
                "轉出 {send} 測試幣\n收款地址：\n{to}\n\n手續費 {fee} 測試幣{}。\n\n{}{}{}確認後立即簽章並發出，無法撤回。",
                if change > 0 { format!("，找零 {change_text} 測試幣回到你的地址") } else { String::new() },
                if caution { "注意：之前有轉帳沒能確認發出，它可能已經發出；這一筆會在它之外另行支付。\n\n" } else { "" },
                if sources.one_source { "注意：這次只有一個節點回應，沒能用另一個節點核對。\n\n" } else { "" },
                if sources.disagree { "注意：兩個節點的回答不一致。\n\n" } else { "" }
            ),
            ok: "簽章並發出",
            cancel: "取消",
        },
        _ => Dialog {
            title: "Confirm the payment",
            body: format!(
                "Send {send} test coins\nto\n{to}\n\nFee {fee} test coins{}.\n\n{}{}{}Once confirmed it is signed and sent, and cannot be undone.",
                if change > 0 { format!("; {change_text} test coins come back to your address as change") } else { String::new() },
                if caution { "Note: an earlier payment did not clearly go out and may have gone out after all; this one would be paid on top of it.\n\n" } else { "" },
                if sources.one_source { "Note: only one node answered, so nothing was checked against the other.\n\n" } else { "" },
                if sources.disagree { "Note: the two nodes disagree.\n\n" } else { "" }
            ),
            ok: "Sign and send",
            cancel: "Cancel",
        },
    }
}

/// The confirmation of removing a wallet whose password is forgotten.
pub fn removal(locale: &str) -> Dialog {
    match locale {
        "zh-Hans" => Dialog {
            title: "从这台设备移除钱包",
            body: "这台设备上的钱包文件将被删除。之后只能用助记词或备份码恢复；没有它们，钱包里的币就再也取不回来。转账记录也会一并删除，还没有明确结果的转账将不再有防止重复付款的保护。".into(),
            ok: "移除",
            cancel: "取消",
        },
        "zh-Hant" => Dialog {
            title: "從這台裝置移除錢包",
            body: "這台裝置上的錢包檔案將被刪除。之後只能用助記詞或備份碼還原；沒有它們，錢包裡的幣就再也取不回來。轉帳記錄也會一併刪除，還沒有明確結果的轉帳將不再有防止重複付款的保護。".into(),
            ok: "移除",
            cancel: "取消",
        },
        _ => Dialog {
            title: "Remove the wallet from this device",
            body: "The wallet file on this device will be deleted. Only the recovery words or the backup code bring it back; without them, its coins are lost for good. Its record of payments goes too: a payment whose outcome is still unclear is no longer guarded against being paid twice.".into(),
            ok: "Remove",
            cancel: "Cancel",
        },
    }
}

/// Shows the dialog over the main window and waits for the answer; true only for the confirming button.
pub async fn ask(app: &AppHandle, dialog: Dialog) -> bool {
    let builder = app
        .dialog()
        .message(dialog.body)
        .title(dialog.title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(dialog.ok.into(), dialog.cancel.into()));
    #[cfg(desktop)]
    let builder = match app.get_webview_window("main") {
        Some(window) => builder.parent(&window),
        None => builder,
    };
    tauri::async_runtime::spawn_blocking(move || builder.blocking_show()).await.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn figures_and_languages() {
        assert_eq!(coins(150_000_000), "1.5");
        assert_eq!(coins(1), "0.00000001");
        assert_eq!(coins(200_000_000), "2");
        assert_eq!(locale("auto", Some("zh-Hant")), "zh-Hant");
        assert_eq!(locale("en", Some("zh-Hans")), "en");
        assert_eq!(locale("auto", Some("<script>")), "en");
        let d = payment("zh-Hans", 10_000_000, "tb1zexample", 2_090, 0, false, Flags::default());
        assert!(d.body.contains("0.1 测试币") && d.body.contains("tb1zexample") && !d.body.contains("找零") && !d.body.contains("注意"));
        assert!(payment("en", 1, "x", 1, 5, false, Flags::default()).body.contains("change"));
        assert!(payment("zh-Hant", 1, "x", 1, 0, true, Flags::default()).body.contains("注意"));
    }

    #[test]
    fn source_notices_are_independent_and_precede_the_closing_sentence() {
        for (locale, one, disagree, closing, earlier) in [
            ("zh-Hans", "注意：这次只有一个节点回应，没能用另一个节点核对。", "注意：两个节点的回答不一致。", "确认后立即", "之前有转账"),
            ("zh-Hant", "注意：這次只有一個節點回應，沒能用另一個節點核對。", "注意：兩個節點的回答不一致。", "確認後立即", "之前有轉帳"),
            ("en", "Note: only one node answered, so nothing was checked against the other.", "Note: the two nodes disagree.", "Once confirmed", "an earlier payment"),
        ] {
            for one_source in [false, true] {
                for sources_disagree in [false, true] {
                    let flags = Flags { one_source, disagree: sources_disagree };
                    let dialog = payment(locale, 1, "tb1ztest", 2, 0, flags.caution(), flags);
                    assert_eq!(dialog.body.contains(one), one_source);
                    assert_eq!(dialog.body.contains(disagree), sources_disagree);
                    assert_eq!(dialog.body.contains(earlier), flags.caution());
                    for notice in [one, disagree] {
                        if let Some(at) = dialog.body.find(notice) {
                            assert!(at < dialog.body.find(closing).unwrap());
                        }
                    }
                }
            }
        }
    }
}
