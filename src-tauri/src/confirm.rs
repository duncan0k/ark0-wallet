//! Confirmations in a dialog of the operating system, outside the web view: what the web view cannot
//! answer for the user. A payment is signed, and a wallet removed without its password, only after one.
//! The wording is the core's own, in the interface's language, with the figures of the frozen plan.
use crate::sources::Flags;
use tauri::{AppHandle, Manager};
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

/// The message for a second instance, in every language the wallet has: it runs before any window exists, so
/// there is no language setting or system language to read.
const RUNNING_MESSAGE: &str = "钱包已经在运行，请使用已经打开的窗口。\n錢包已經在執行，請使用已經開啟的視窗。\nThe wallet is already running. Use the window that is already open.";

/// No AppState is installed in this instance, so no command can read or change wallet files. The process ends
/// once the message is closed.
pub fn already_running(app: &AppHandle) {
    let builder = app.dialog().message(RUNNING_MESSAGE)
        .title(app.config().product_name.as_deref().unwrap_or(env!("CARGO_PKG_NAME")))
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCustom("OK".into()));
    let app = app.clone();
    builder.show(move |_| app.exit(0));
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

/// Recovery material is shown only after the user confirms outside the web view.
pub fn recovery(locale: &str, legacy: bool) -> Dialog {
    match (locale, legacy) {
        ("zh-Hans", false) => Dialog {
            title: "显示助记词",
            body: "这个钱包的助记词将显示在窗口里。看到它的人能拿走钱包里的全部币。请确认周围没有人，屏幕也没有在录制或共享。".into(),
            ok: "显示",
            cancel: "取消",
        },
        ("zh-Hans", true) => Dialog {
            title: "显示备份码",
            body: "这个钱包的备份码将显示在窗口里。看到它的人能拿走钱包里的全部币。请确认周围没有人，屏幕也没有在录制或共享。".into(),
            ok: "显示",
            cancel: "取消",
        },
        ("zh-Hant", false) => Dialog {
            title: "顯示助記詞",
            body: "這個錢包的助記詞將顯示在視窗裡。看到它的人能拿走錢包裡的全部幣。請確認周圍沒有人，螢幕也沒有在錄製或共享。".into(),
            ok: "顯示",
            cancel: "取消",
        },
        ("zh-Hant", true) => Dialog {
            title: "顯示備份碼",
            body: "這個錢包的備份碼將顯示在視窗裡。看到它的人能拿走錢包裡的全部幣。請確認周圍沒有人，螢幕也沒有在錄製或共享。".into(),
            ok: "顯示",
            cancel: "取消",
        },
        (_, false) => Dialog {
            title: "Show the recovery words",
            body: "This wallet's recovery words will be shown in the window. Anyone who sees them can take every coin in the wallet. Make sure no one is watching and the screen is not being recorded or shared.".into(),
            ok: "Show",
            cancel: "Cancel",
        },
        (_, true) => Dialog {
            title: "Show the backup code",
            body: "This wallet's backup code will be shown in the window. Anyone who sees it can take every coin in the wallet. Make sure no one is watching and the screen is not being recorded or shared.".into(),
            ok: "Show",
            cancel: "Cancel",
        },
    }
}

/// The node receives a broadcastable transaction even though the wallet does not broadcast it.
pub fn drill(locale: &str, amount: u64, fee: u64) -> Dialog {
    let (amount, fee) = (coins(amount), coins(fee));
    match locale {
        "zh-Hans" => Dialog {
            title: "演练：签一笔转回自己的交易",
            body: format!("将用混合地址里最大的一枚币（{amount} 测试币）签一笔转回同一地址的交易，交给节点核对，钱包不会广播它。\n\n交给节点的是一笔有效交易，节点或别人仍可能把它发出去：那样这枚币会回到同一地址，扣掉手续费 {fee} 测试币。"),
            ok: "签名并交给节点核对",
            cancel: "取消",
        },
        "zh-Hant" => Dialog {
            title: "演練：簽一筆轉回自己的交易",
            body: format!("將用混合地址裡最大的一枚幣（{amount} 測試幣）簽一筆轉回同一地址的交易，交給節點核對，錢包不會廣播它。\n\n交給節點的是一筆有效交易，節點或別人仍可能把它發出去：那樣這枚幣會回到同一地址，扣掉手續費 {fee} 測試幣。"),
            ok: "簽章並交給節點核對",
            cancel: "取消",
        },
        _ => Dialog {
            title: "Drill: sign a transfer back to yourself",
            body: format!("The largest coin in the mixed address ({amount} test coins) will be signed over to the same address and given to the node to check. The wallet will not broadcast it.\n\nWhat the node gets is a valid transaction, and the node or anyone else may still send it: the coin would then come back to the same address, less the fee of {fee} test coins."),
            ok: "Sign and give to the node",
            cancel: "Cancel",
        },
    }
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
    fn recovery_dialogs_name_the_secret_and_warn_in_each_language() {
        for (locale, words_title, code_title, words_body, code_body, ok, cancel) in [
            ("en", "Show the recovery words", "Show the backup code",
                "This wallet's recovery words will be shown in the window. Anyone who sees them can take every coin in the wallet. Make sure no one is watching and the screen is not being recorded or shared.",
                "This wallet's backup code will be shown in the window. Anyone who sees it can take every coin in the wallet. Make sure no one is watching and the screen is not being recorded or shared.", "Show", "Cancel"),
            ("zh-Hans", "显示助记词", "显示备份码",
                "这个钱包的助记词将显示在窗口里。看到它的人能拿走钱包里的全部币。请确认周围没有人，屏幕也没有在录制或共享。",
                "这个钱包的备份码将显示在窗口里。看到它的人能拿走钱包里的全部币。请确认周围没有人，屏幕也没有在录制或共享。", "显示", "取消"),
            ("zh-Hant", "顯示助記詞", "顯示備份碼",
                "這個錢包的助記詞將顯示在視窗裡。看到它的人能拿走錢包裡的全部幣。請確認周圍沒有人，螢幕也沒有在錄製或共享。",
                "這個錢包的備份碼將顯示在視窗裡。看到它的人能拿走錢包裡的全部幣。請確認周圍沒有人，螢幕也沒有在錄製或共享。", "顯示", "取消"),
        ] {
            for (legacy, title, body) in [(false, words_title, words_body), (true, code_title, code_body)] {
                let dialog = recovery(locale, legacy);
                assert_eq!((dialog.title, dialog.body.as_str(), dialog.ok, dialog.cancel), (title, body, ok, cancel));
            }
        }
    }

    #[test]
    fn drill_dialogs_show_the_coin_fee_and_broadcast_warning_in_two_paragraphs() {
        for (locale, title, first, second, ok, cancel) in [
            ("en", "Drill: sign a transfer back to yourself",
                "The largest coin in the mixed address (1.5 test coins) will be signed over to the same address and given to the node to check. The wallet will not broadcast it.",
                "What the node gets is a valid transaction, and the node or anyone else may still send it: the coin would then come back to the same address, less the fee of 0.0000209 test coins.", "Sign and give to the node", "Cancel"),
            ("zh-Hans", "演练：签一笔转回自己的交易",
                "将用混合地址里最大的一枚币（1.5 测试币）签一笔转回同一地址的交易，交给节点核对，钱包不会广播它。",
                "交给节点的是一笔有效交易，节点或别人仍可能把它发出去：那样这枚币会回到同一地址，扣掉手续费 0.0000209 测试币。", "签名并交给节点核对", "取消"),
            ("zh-Hant", "演練：簽一筆轉回自己的交易",
                "將用混合地址裡最大的一枚幣（1.5 測試幣）簽一筆轉回同一地址的交易，交給節點核對，錢包不會廣播它。",
                "交給節點的是一筆有效交易，節點或別人仍可能把它發出去：那樣這枚幣會回到同一地址，扣掉手續費 0.0000209 測試幣。", "簽章並交給節點核對", "取消"),
        ] {
            let dialog = drill(locale, 150_000_000, 2_090);
            assert_eq!((dialog.title, dialog.ok, dialog.cancel), (title, ok, cancel));
            assert_eq!(dialog.body.split("\n\n").collect::<Vec<_>>(), vec![first, second]);
        }
    }

    #[test]
    fn already_running_says_it_in_every_language() {
        let lines: Vec<&str> = RUNNING_MESSAGE.split('\n').collect();
        assert_eq!(lines, vec![
            "钱包已经在运行，请使用已经打开的窗口。",
            "錢包已經在執行，請使用已經開啟的視窗。",
            "The wallet is already running. Use the window that is already open.",
        ]);
    }

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
