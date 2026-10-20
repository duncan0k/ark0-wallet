//! Confirmations in a dialog of the operating system, outside the web view: what the web view cannot
//! answer for the user. Signing, revealing recovery material, removing a wallet and changing its password
//! require one.
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
        "ja" => "ja",
        "ko" => "ko",
        "ru" => "ru",
        "es" => "es",
        _ => "en",
    }
}

/// The message for a second instance, in every language the wallet has: it runs before any window exists, so
/// there is no language setting or system language to read.
const RUNNING_MESSAGE: &str = "钱包已经在运行，请使用已经打开的窗口。\n錢包已經在執行，請使用已經開啟的視窗。\nThe wallet is already running. Use the window that is already open.\nウォレットはすでに起動しています。開いているウィンドウをお使いください。\n지갑이 이미 실행 중입니다. 이미 열려 있는 창을 사용하세요.\nКошелёк уже запущен. Пользуйтесь окном, которое уже открыто.\nLa billetera ya se está ejecutando. Usa la ventana que está abierta.";

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

#[cfg(test)]
impl Dialog {
    pub(crate) fn body(&self) -> &str {
        &self.body
    }
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
        ("ja", false) => Dialog {
            title: "リカバリーワードを表示",
            body: "このウォレットのリカバリーワードがウィンドウに表示されます。これを見た人は、ウォレットのコインをすべて持ち去ることができます。周りに誰もいないこと、画面が録画も共有もされていないことを確かめてください。".into(),
            ok: "表示",
            cancel: "キャンセル",
        },
        ("ja", true) => Dialog {
            title: "バックアップコードを表示",
            body: "このウォレットのバックアップコードがウィンドウに表示されます。これを見た人は、ウォレットのコインをすべて持ち去ることができます。周りに誰もいないこと、画面が録画も共有もされていないことを確かめてください。".into(),
            ok: "表示",
            cancel: "キャンセル",
        },
        ("ko", false) => Dialog {
            title: "복구 단어 보기",
            body: "이 지갑의 복구 단어가 창에 표시됩니다. 이 단어를 본 사람은 누구나 지갑의 코인을 모두 가져갈 수 있습니다. 주변에 보는 사람이 없는지, 화면이 녹화되거나 공유되고 있지 않은지 확인하세요.".into(),
            ok: "보기",
            cancel: "취소",
        },
        ("ko", true) => Dialog {
            title: "백업 코드 보기",
            body: "이 지갑의 백업 코드가 창에 표시됩니다. 이 코드를 본 사람은 누구나 지갑의 코인을 모두 가져갈 수 있습니다. 주변에 보는 사람이 없는지, 화면이 녹화되거나 공유되고 있지 않은지 확인하세요.".into(),
            ok: "보기",
            cancel: "취소",
        },
        ("ru", false) => Dialog {
            title: "Показать слова для восстановления",
            body: "Слова для восстановления этого кошелька будут показаны в окне. Тот, кто их увидит, сможет забрать все монеты из кошелька. Убедитесь, что рядом никого нет, а запись и демонстрация экрана выключены.".into(),
            ok: "Показать",
            cancel: "Отмена",
        },
        ("ru", true) => Dialog {
            title: "Показать резервный код",
            body: "Резервный код этого кошелька будет показан в окне. Тот, кто его увидит, сможет забрать все монеты из кошелька. Убедитесь, что рядом никого нет, а запись и демонстрация экрана выключены.".into(),
            ok: "Показать",
            cancel: "Отмена",
        },
        ("es", false) => Dialog {
            title: "Mostrar las palabras de recuperación",
            body: "Las palabras de recuperación de esta billetera se mostrarán en la ventana. Quien las vea puede llevarse todas las monedas de la billetera. Asegúrate de que nadie esté mirando y de que la pantalla no se esté grabando ni compartiendo.".into(),
            ok: "Mostrar",
            cancel: "Cancelar",
        },
        ("es", true) => Dialog {
            title: "Mostrar el código de respaldo",
            body: "El código de respaldo de esta billetera se mostrará en la ventana. Quien lo vea puede llevarse todas las monedas de la billetera. Asegúrate de que nadie esté mirando y de que la pantalla no se esté grabando ni compartiendo.".into(),
            ok: "Mostrar",
            cancel: "Cancelar",
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
        "ja" => Dialog {
            title: "演習：自分に戻す取引に署名",
            body: format!("混合アドレスでいちばん大きいコイン 1 枚（{amount} テストコイン）を使い、同じアドレスに戻す取引に署名して、ノードに検証してもらいます。ウォレットはこの取引をブロードキャストしません。\n\nノードに渡すのは有効な取引なので、ノードやほかの誰かがそれを送信する可能性はあります：その場合、このコインは手数料 {fee} テストコインを差し引いて、同じアドレスに戻ります。"),
            ok: "署名してノードで検証",
            cancel: "キャンセル",
        },
        "ko" => Dialog {
            title: "훈련: 나에게 되돌려 보내는 트랜잭션에 서명",
            body: format!("혼합 주소에서 가장 큰 코인 하나({amount} 테스트 코인)를 같은 주소로 되돌려 보내는 트랜잭션에 서명해 노드에 검사를 맡깁니다. 지갑은 이 트랜잭션을 브로드캐스트하지 않습니다.\n\n노드에 넘기는 것은 유효한 트랜잭션이므로, 노드나 다른 사람이 이를 네트워크에 보낼 수도 있습니다. 그러면 이 코인은 수수료 {fee} 테스트 코인을 뺀 채 같은 주소로 돌아옵니다."),
            ok: "서명하고 노드에 검사 맡기기",
            cancel: "취소",
        },
        "ru" => Dialog {
            title: "Учения: подписать перевод обратно себе",
            body: format!("Кошелёк подпишет перевод самой крупной монеты смешанного адреса (сумма в тестовых монетах: {amount}) обратно на этот же адрес и передаст его узлу на проверку. В сеть кошелёк его не отправит.\n\nУзел получит действительную транзакцию, и он сам или кто-то другой всё равно может отправить её в сеть: тогда монета вернётся на тот же адрес за вычетом комиссии (в тестовых монетах: {fee})."),
            ok: "Подписать и передать узлу",
            cancel: "Отмена",
        },
        "es" => Dialog {
            title: "Simulacro: firmar una transferencia de vuelta a ti",
            body: format!("Con la moneda más grande de la dirección mixta (cantidad en monedas de prueba: {amount}) se firmará una transferencia de vuelta a la misma dirección, que se entregará al nodo para que la compruebe. La billetera no la difundirá por la red.\n\nLo que recibe el nodo es una transacción válida, y el nodo u otra persona aún podrían enviarla: en ese caso, la moneda volvería a la misma dirección, descontada la comisión (en monedas de prueba: {fee})."),
            ok: "Firmar y entregar al nodo",
            cancel: "Cancelar",
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
        "ja" => Dialog {
            title: "送金の確認",
            body: format!(
                "{send} テストコインを送金\n送金先アドレス：\n{to}\n\n手数料は {fee} テストコインです{}。\n\n{}{}{}確定すると、すぐに署名して送信され、取り消すことはできません。",
                if change > 0 { format!("。おつりの {change_text} テストコインはあなたのアドレスに戻ります") } else { String::new() },
                if caution { "注意：以前の送金が送信されたかどうか確認できませんでしたが、実際には送信されている可能性があります。この送金は、それとは別に支払われます。\n\n" } else { "" },
                if sources.one_source { "注意：今回は 1 台のノードしか応答しなかったため、もう 1 台のノードと照合できませんでした。\n\n" } else { "" },
                if sources.disagree { "注意：2 台のノードの回答が一致しません。\n\n" } else { "" }
            ),
            ok: "署名して送金",
            cancel: "キャンセル",
        },
        "ko" => Dialog {
            title: "송금 확인",
            body: format!(
                "{send} 테스트 코인을 보냅니다\n받는 주소:\n{to}\n\n수수료는 {fee} 테스트 코인입니다{}.\n\n{}{}{}확인하면 바로 서명해 보내며, 되돌릴 수 없습니다.",
                if change > 0 { format!(". 잔돈 {change_text} 테스트 코인은 내 주소로 돌아옵니다") } else { String::new() },
                if caution { "주의: 전송 여부가 확인되지 않은 이전 송금이 있으며, 그 송금은 실제로 이미 전송되었을 수 있습니다. 이번 송금은 그 송금에 더해 따로 지급됩니다.\n\n" } else { "" },
                if sources.one_source { "주의: 이번에는 노드 하나만 응답해서, 다른 노드와 대조하지 못했습니다.\n\n" } else { "" },
                if sources.disagree { "주의: 두 노드의 답이 서로 다릅니다.\n\n" } else { "" }
            ),
            ok: "서명하고 보내기",
            cancel: "취소",
        },
        "ru" => Dialog {
            title: "Подтверждение перевода",
            body: format!(
                "Сумма перевода в тестовых монетах: {send}\nАдрес получателя:\n{to}\n\nКомиссия в тестовых монетах: {fee}{}.\n\n{}{}{}После подтверждения перевод будет сразу подписан и отправлен; отменить его будет нельзя.",
                if change > 0 { format!("; сдача, которая вернётся на ваш адрес: {change_text}") } else { String::new() },
                if caution { "Внимание: отправку более раннего перевода не удалось подтвердить, и, возможно, он всё-таки ушёл; этот перевод не заменит его, а уйдёт в дополнение к нему.\n\n" } else { "" },
                if sources.one_source { "Внимание: в этот раз ответил только один узел, поэтому ничего не удалось сверить со вторым.\n\n" } else { "" },
                if sources.disagree { "Внимание: ответы двух узлов расходятся.\n\n" } else { "" }
            ),
            ok: "Подписать и отправить",
            cancel: "Отмена",
        },
        "es" => Dialog {
            title: "Confirmar la transferencia",
            body: format!(
                "Cantidad a enviar en monedas de prueba: {send}\nDirección de destino:\n{to}\n\nComisión en monedas de prueba: {fee}{}.\n\n{}{}{}Al confirmar, se firmará y se enviará de inmediato, y no se podrá deshacer.",
                if change > 0 { format!("; cambio que vuelve a tu dirección: {change_text}") } else { String::new() },
                if caution { "Atención: una transferencia anterior no se pudo confirmar como enviada, pero puede que sí haya salido; esta se pagaría además de aquella.\n\n" } else { "" },
                if sources.one_source { "Atención: esta vez solo respondió un nodo, así que nada se pudo contrastar con el otro.\n\n" } else { "" },
                if sources.disagree { "Atención: las respuestas de los dos nodos no coinciden.\n\n" } else { "" }
            ),
            ok: "Firmar y enviar",
            cancel: "Cancelar",
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

/// The confirmation of removing a wallet, with its password or when the password is forgotten.
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
            body: "這台裝置上的錢包檔案將被刪除。之後只能用助記詞或備份碼還原；沒有它們，錢包裡的幣就再也取不回來。轉帳紀錄也會一併刪除，還沒有明確結果的轉帳將不再有防止重複付款的保護。".into(),
            ok: "移除",
            cancel: "取消",
        },
        "ja" => Dialog {
            title: "このデバイスからウォレットを削除",
            body: "このデバイス上のウォレットのファイルが削除されます。その後はリカバリーワードかバックアップコードでしか復元できず、どちらもなければ、ウォレットのコインは二度と取り戻せません。送金の履歴も一緒に削除され、結果がまだはっきりしない送金については、二重払いを防ぐ保護がなくなります。".into(),
            ok: "削除",
            cancel: "キャンセル",
        },
        "ko" => Dialog {
            title: "이 기기에서 지갑 삭제",
            body: "이 기기의 지갑 파일이 삭제됩니다. 이후에는 복구 단어나 백업 코드가 있어야만 되살릴 수 있고, 없으면 지갑의 코인은 다시는 되찾을 수 없습니다. 송금 기록도 함께 삭제되므로, 결과가 아직 확실하지 않은 송금은 더 이상 중복 지급을 막는 보호를 받지 못합니다.".into(),
            ok: "삭제",
            cancel: "취소",
        },
        "ru" => Dialog {
            title: "Удалить кошелёк с этого устройства",
            body: "Файл кошелька на этом устройстве будет удалён. Вернуть кошелёк можно будет только по словам для восстановления или резервному коду; без них его монеты будут потеряны навсегда. История переводов тоже будет удалена: для переводов, результат которых ещё не ясен, защиты от повторной оплаты больше не будет.".into(),
            ok: "Удалить",
            cancel: "Отмена",
        },
        "es" => Dialog {
            title: "Eliminar la billetera de este dispositivo",
            body: "Se borrará el archivo de la billetera de este dispositivo. Después, solo podrás restaurarla con las palabras de recuperación o el código de respaldo; sin ellos, las monedas de la billetera se pierden para siempre. También se borra su registro de transferencias: una transferencia cuyo resultado aún no está claro deja de estar protegida contra un pago duplicado.".into(),
            ok: "Eliminar",
            cancel: "Cancelar",
        },
        _ => Dialog {
            title: "Remove the wallet from this device",
            body: "The wallet file on this device will be deleted. Only the recovery words or the backup code bring it back; without them, its coins are lost for good. Its record of payments goes too: a payment whose outcome is still unclear is no longer guarded against being paid twice.".into(),
            ok: "Remove",
            cancel: "Cancel",
        },
    }
}

/// The confirmation of changing the password that opens this wallet on this device.
pub fn password_change(locale: &str) -> Dialog {
    match locale {
        "zh-Hans" => Dialog {
            title: "修改密码",
            body: "从现在起，只有新密码能在这台设备上打开这个钱包，旧密码将不再有效。".into(),
            ok: "修改",
            cancel: "取消",
        },
        "zh-Hant" => Dialog {
            title: "修改密碼",
            body: "從現在起，只有新密碼能在這台裝置上開啟這個錢包，舊密碼將不再有效。".into(),
            ok: "修改",
            cancel: "取消",
        },
        "ja" => Dialog {
            title: "パスワードを変更",
            body: "今後、このデバイスでこのウォレットを開けるのは新しいパスワードだけになり、古いパスワードは使えなくなります。".into(),
            ok: "変更",
            cancel: "キャンセル",
        },
        "ko" => Dialog {
            title: "비밀번호 변경",
            body: "지금부터는 이 기기에서 새 비밀번호로만 이 지갑을 열 수 있으며, 예전 비밀번호는 더 이상 쓸 수 없습니다.".into(),
            ok: "변경",
            cancel: "취소",
        },
        "ru" => Dialog {
            title: "Сменить пароль",
            body: "С этого момента открыть этот кошелёк на этом устройстве можно будет только новым паролем; старый перестанет действовать.".into(),
            ok: "Сменить",
            cancel: "Отмена",
        },
        "es" => Dialog {
            title: "Cambiar la contraseña",
            body: "A partir de ahora, solo la nueva contraseña abrirá esta billetera en este dispositivo; la anterior dejará de funcionar.".into(),
            ok: "Cambiar",
            cancel: "Cancelar",
        },
        _ => Dialog {
            title: "Change the password",
            body: "From now on only the new password will open this wallet on this device; the old one will no longer work.".into(),
            ok: "Change",
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
    fn password_change_dialogs_in_each_language() {
        for (locale, title, body, ok, cancel) in [
            ("en", "Change the password", "From now on only the new password will open this wallet on this device; the old one will no longer work.", "Change", "Cancel"),
            ("zh-Hans", "修改密码", "从现在起，只有新密码能在这台设备上打开这个钱包，旧密码将不再有效。", "修改", "取消"),
            ("zh-Hant", "修改密碼", "從現在起，只有新密碼能在這台裝置上開啟這個錢包，舊密碼將不再有效。", "修改", "取消"),
            ("ja", "パスワードを変更", "今後、このデバイスでこのウォレットを開けるのは新しいパスワードだけになり、古いパスワードは使えなくなります。", "変更", "キャンセル"),
            ("ko", "비밀번호 변경", "지금부터는 이 기기에서 새 비밀번호로만 이 지갑을 열 수 있으며, 예전 비밀번호는 더 이상 쓸 수 없습니다.", "변경", "취소"),
            ("ru", "Сменить пароль", "С этого момента открыть этот кошелёк на этом устройстве можно будет только новым паролем; старый перестанет действовать.", "Сменить", "Отмена"),
            ("es", "Cambiar la contraseña", "A partir de ahora, solo la nueva contraseña abrirá esta billetera en este dispositivo; la anterior dejará de funcionar.", "Cambiar", "Cancelar"),
        ] {
            let dialog = password_change(locale);
            assert_eq!((dialog.title, dialog.body.as_str(), dialog.ok, dialog.cancel), (title, body, ok, cancel));
        }
    }

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
            ("ja", "リカバリーワードを表示", "バックアップコードを表示",
                "このウォレットのリカバリーワードがウィンドウに表示されます。これを見た人は、ウォレットのコインをすべて持ち去ることができます。周りに誰もいないこと、画面が録画も共有もされていないことを確かめてください。",
                "このウォレットのバックアップコードがウィンドウに表示されます。これを見た人は、ウォレットのコインをすべて持ち去ることができます。周りに誰もいないこと、画面が録画も共有もされていないことを確かめてください。", "表示", "キャンセル"),
            ("ko", "복구 단어 보기", "백업 코드 보기",
                "이 지갑의 복구 단어가 창에 표시됩니다. 이 단어를 본 사람은 누구나 지갑의 코인을 모두 가져갈 수 있습니다. 주변에 보는 사람이 없는지, 화면이 녹화되거나 공유되고 있지 않은지 확인하세요.",
                "이 지갑의 백업 코드가 창에 표시됩니다. 이 코드를 본 사람은 누구나 지갑의 코인을 모두 가져갈 수 있습니다. 주변에 보는 사람이 없는지, 화면이 녹화되거나 공유되고 있지 않은지 확인하세요.", "보기", "취소"),
            ("ru", "Показать слова для восстановления", "Показать резервный код",
                "Слова для восстановления этого кошелька будут показаны в окне. Тот, кто их увидит, сможет забрать все монеты из кошелька. Убедитесь, что рядом никого нет, а запись и демонстрация экрана выключены.",
                "Резервный код этого кошелька будет показан в окне. Тот, кто его увидит, сможет забрать все монеты из кошелька. Убедитесь, что рядом никого нет, а запись и демонстрация экрана выключены.", "Показать", "Отмена"),
            ("es", "Mostrar las palabras de recuperación", "Mostrar el código de respaldo",
                "Las palabras de recuperación de esta billetera se mostrarán en la ventana. Quien las vea puede llevarse todas las monedas de la billetera. Asegúrate de que nadie esté mirando y de que la pantalla no se esté grabando ni compartiendo.",
                "El código de respaldo de esta billetera se mostrará en la ventana. Quien lo vea puede llevarse todas las monedas de la billetera. Asegúrate de que nadie esté mirando y de que la pantalla no se esté grabando ni compartiendo.", "Mostrar", "Cancelar"),
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
            ("ja", "演習：自分に戻す取引に署名",
                "混合アドレスでいちばん大きいコイン 1 枚（1.5 テストコイン）を使い、同じアドレスに戻す取引に署名して、ノードに検証してもらいます。ウォレットはこの取引をブロードキャストしません。",
                "ノードに渡すのは有効な取引なので、ノードやほかの誰かがそれを送信する可能性はあります：その場合、このコインは手数料 0.0000209 テストコインを差し引いて、同じアドレスに戻ります。", "署名してノードで検証", "キャンセル"),
            ("ko", "훈련: 나에게 되돌려 보내는 트랜잭션에 서명",
                "혼합 주소에서 가장 큰 코인 하나(1.5 테스트 코인)를 같은 주소로 되돌려 보내는 트랜잭션에 서명해 노드에 검사를 맡깁니다. 지갑은 이 트랜잭션을 브로드캐스트하지 않습니다.",
                "노드에 넘기는 것은 유효한 트랜잭션이므로, 노드나 다른 사람이 이를 네트워크에 보낼 수도 있습니다. 그러면 이 코인은 수수료 0.0000209 테스트 코인을 뺀 채 같은 주소로 돌아옵니다.", "서명하고 노드에 검사 맡기기", "취소"),
            ("ru", "Учения: подписать перевод обратно себе",
                "Кошелёк подпишет перевод самой крупной монеты смешанного адреса (сумма в тестовых монетах: 1.5) обратно на этот же адрес и передаст его узлу на проверку. В сеть кошелёк его не отправит.",
                "Узел получит действительную транзакцию, и он сам или кто-то другой всё равно может отправить её в сеть: тогда монета вернётся на тот же адрес за вычетом комиссии (в тестовых монетах: 0.0000209).", "Подписать и передать узлу", "Отмена"),
            ("es", "Simulacro: firmar una transferencia de vuelta a ti",
                "Con la moneda más grande de la dirección mixta (cantidad en monedas de prueba: 1.5) se firmará una transferencia de vuelta a la misma dirección, que se entregará al nodo para que la compruebe. La billetera no la difundirá por la red.",
                "Lo que recibe el nodo es una transacción válida, y el nodo u otra persona aún podrían enviarla: en ese caso, la moneda volvería a la misma dirección, descontada la comisión (en monedas de prueba: 0.0000209).", "Firmar y entregar al nodo", "Cancelar"),
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
            "ウォレットはすでに起動しています。開いているウィンドウをお使いください。",
            "지갑이 이미 실행 중입니다. 이미 열려 있는 창을 사용하세요.",
            "Кошелёк уже запущен. Пользуйтесь окном, которое уже открыто.",
            "La billetera ya se está ejecutando. Usa la ventana que está abierta.",
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
        for code in ["ja", "ko", "ru", "es"] {
            assert_eq!(locale(code, Some("zh-Hans")), code);
            assert_eq!(locale("auto", Some(code)), code);
        }
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
            ("ja", "注意：今回は 1 台のノードしか応答しなかったため、もう 1 台のノードと照合できませんでした。", "注意：2 台のノードの回答が一致しません。", "確定すると、すぐ", "以前の送金が送信"),
            ("ko", "주의: 이번에는 노드 하나만 응답해서, 다른 노드와 대조하지 못했습니다.", "주의: 두 노드의 답이 서로 다릅니다.", "확인하면 바로 ", "전송 여부가 확"),
            ("ru", "Внимание: в этот раз ответил только один узел, поэтому ничего не удалось сверить со вторым.", "Внимание: ответы двух узлов расходятся.", "После по", "отправку"),
            ("es", "Atención: esta vez solo respondió un nodo, así que nada se pudo contrastar con el otro.", "Atención: las respuestas de los dos nodos no coinciden.", "Al confi", "una tran"),
        ] {
            for one_source in [false, true] {
                for sources_disagree in [false, true] {
                    let flags = Flags { one_source, disagree: sources_disagree };
                    let dialog = payment(locale, 1, "tb1ztest", 2, 0, false, flags);
                    assert_eq!(dialog.body.contains(one), one_source);
                    assert_eq!(dialog.body.contains(disagree), sources_disagree);
                    assert!(!dialog.body.contains(earlier));
                    for notice in [one, disagree] {
                        if let Some(at) = dialog.body.find(notice) {
                            assert!(at < dialog.body.find(closing).unwrap());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn payment_dialogs_in_each_language_with_and_without_change_and_with_each_note() {
        for (locale, plain, with_change, closing, caution, one, disagree) in [
            (
                "zh-Hans",
                "转出 1.5 测试币\n收款地址：\ntb1ztest\n\n手续费 0.0000209 测试币。\n\n确认后立即签名并发出，无法撤回。",
                "转出 1.5 测试币\n收款地址：\ntb1ztest\n\n手续费 0.0000209 测试币，找零 0.3 测试币回到你的地址。\n\n确认后立即签名并发出，无法撤回。",
                "确认后立即",
                "注意：之前有转账没能确认发出，它可能已经发出；这一笔会在它之外另行支付。",
                "注意：这次只有一个节点回应，没能用另一个节点核对。",
                "注意：两个节点的回答不一致。",
            ),
            (
                "zh-Hant",
                "轉出 1.5 測試幣\n收款地址：\ntb1ztest\n\n手續費 0.0000209 測試幣。\n\n確認後立即簽章並發出，無法撤回。",
                "轉出 1.5 測試幣\n收款地址：\ntb1ztest\n\n手續費 0.0000209 測試幣，找零 0.3 測試幣回到你的地址。\n\n確認後立即簽章並發出，無法撤回。",
                "確認後立即",
                "注意：之前有轉帳沒能確認發出，它可能已經發出；這一筆會在它之外另行支付。",
                "注意：這次只有一個節點回應，沒能用另一個節點核對。",
                "注意：兩個節點的回答不一致。",
            ),
            (
                "en",
                "Send 1.5 test coins\nto\ntb1ztest\n\nFee 0.0000209 test coins.\n\nOnce confirmed it is signed and sent, and cannot be undone.",
                "Send 1.5 test coins\nto\ntb1ztest\n\nFee 0.0000209 test coins; 0.3 test coins come back to your address as change.\n\nOnce confirmed it is signed and sent, and cannot be undone.",
                "Once confirmed",
                "Note: an earlier payment did not clearly go out and may have gone out after all; this one would be paid on top of it.",
                "Note: only one node answered, so nothing was checked against the other.",
                "Note: the two nodes disagree.",
            ),
            (
                "ja",
                "1.5 テストコインを送金\n送金先アドレス：\ntb1ztest\n\n手数料は 0.0000209 テストコインです。\n\n確定すると、すぐに署名して送信され、取り消すことはできません。",
                "1.5 テストコインを送金\n送金先アドレス：\ntb1ztest\n\n手数料は 0.0000209 テストコインです。おつりの 0.3 テストコインはあなたのアドレスに戻ります。\n\n確定すると、すぐに署名して送信され、取り消すことはできません。",
                "確定すると",
                "注意：以前の送金が送信されたかどうか確認できませんでしたが、実際には送信されている可能性があります。この送金は、それとは別に支払われます。",
                "注意：今回は 1 台のノードしか応答しなかったため、もう 1 台のノードと照合できませんでした。",
                "注意：2 台のノードの回答が一致しません。",
            ),
            (
                "ko",
                "1.5 테스트 코인을 보냅니다\n받는 주소:\ntb1ztest\n\n수수료는 0.0000209 테스트 코인입니다.\n\n확인하면 바로 서명해 보내며, 되돌릴 수 없습니다.",
                "1.5 테스트 코인을 보냅니다\n받는 주소:\ntb1ztest\n\n수수료는 0.0000209 테스트 코인입니다. 잔돈 0.3 테스트 코인은 내 주소로 돌아옵니다.\n\n확인하면 바로 서명해 보내며, 되돌릴 수 없습니다.",
                "확인하면 바로",
                "주의: 전송 여부가 확인되지 않은 이전 송금이 있으며, 그 송금은 실제로 이미 전송되었을 수 있습니다. 이번 송금은 그 송금에 더해 따로 지급됩니다.",
                "주의: 이번에는 노드 하나만 응답해서, 다른 노드와 대조하지 못했습니다.",
                "주의: 두 노드의 답이 서로 다릅니다.",
            ),
            (
                "ru",
                "Сумма перевода в тестовых монетах: 1.5\nАдрес получателя:\ntb1ztest\n\nКомиссия в тестовых монетах: 0.0000209.\n\nПосле подтверждения перевод будет сразу подписан и отправлен; отменить его будет нельзя.",
                "Сумма перевода в тестовых монетах: 1.5\nАдрес получателя:\ntb1ztest\n\nКомиссия в тестовых монетах: 0.0000209; сдача, которая вернётся на ваш адрес: 0.3.\n\nПосле подтверждения перевод будет сразу подписан и отправлен; отменить его будет нельзя.",
                "После подтверждения",
                "Внимание: отправку более раннего перевода не удалось подтвердить, и, возможно, он всё-таки ушёл; этот перевод не заменит его, а уйдёт в дополнение к нему.",
                "Внимание: в этот раз ответил только один узел, поэтому ничего не удалось сверить со вторым.",
                "Внимание: ответы двух узлов расходятся.",
            ),
            (
                "es",
                "Cantidad a enviar en monedas de prueba: 1.5\nDirección de destino:\ntb1ztest\n\nComisión en monedas de prueba: 0.0000209.\n\nAl confirmar, se firmará y se enviará de inmediato, y no se podrá deshacer.",
                "Cantidad a enviar en monedas de prueba: 1.5\nDirección de destino:\ntb1ztest\n\nComisión en monedas de prueba: 0.0000209; cambio que vuelve a tu dirección: 0.3.\n\nAl confirmar, se firmará y se enviará de inmediato, y no se podrá deshacer.",
                "Al confirmar",
                "Atención: una transferencia anterior no se pudo confirmar como enviada, pero puede que sí haya salido; esta se pagaría además de aquella.",
                "Atención: esta vez solo respondió un nodo, así que nada se pudo contrastar con el otro.",
                "Atención: las respuestas de los dos nodos no coinciden.",
            ),
        ] {
            // A note goes in front of the closing sentence, as its own paragraph.
            let noted = |notes: &[&str]| {
                let notes: String = notes.iter().map(|n| format!("{n}\n\n")).collect();
                plain.replacen(closing, &format!("{notes}{closing}"), 1)
            };
            let body = |change, caution, one_source, disagree| {
                let flags = Flags { one_source, disagree };
                payment(locale, 150_000_000, "tb1ztest", 2_090, change, caution, flags).body
            };
            assert_eq!(body(0, false, false, false), plain);
            assert_eq!(body(30_000_000, false, false, false), with_change);
            assert_eq!(body(0, true, false, false), noted(&[caution]));
            assert_eq!(body(0, false, true, false), noted(&[one]));
            assert_eq!(body(0, false, false, true), noted(&[disagree]));
            assert_eq!(body(0, true, true, true), noted(&[caution, one, disagree]));
        }
    }

    #[test]
    fn the_newer_languages_have_dialogs_of_their_own() {
        let flags = Flags::default();
        let english = [
            recovery("en", false).title,
            recovery("en", true).title,
            drill("en", 1, 1).title,
            payment("en", 1, "x", 1, 0, false, flags).title,
            removal("en").title,
            password_change("en").title,
        ];
        for locale in ["ja", "ko", "ru", "es"] {
            let dialogs = [
                recovery(locale, false),
                recovery(locale, true),
                drill(locale, 1, 1),
                payment(locale, 1, "x", 1, 0, false, flags),
                removal(locale),
                password_change(locale),
            ];
            for (dialog, english) in dialogs.iter().zip(english) {
                assert_ne!(dialog.title, english, "{locale}");
                assert!(
                    !dialog.body.is_empty() && !dialog.ok.is_empty() && !dialog.cancel.is_empty()
                );
            }
        }
    }

}
