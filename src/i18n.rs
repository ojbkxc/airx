//! i18n 消息表（对齐 Go resources/i18n/*.toml，7 语言 34 键）
//!
//! Go 用 go-i18n + TOML 文件运行时加载；Rust 侧编译期内置（免资源文件依赖），
//! 键与译文逐条对照 Go en/es/fr/ko/ru/zh_CN/zh_TW 的 `one` 值。
//! 未知语言回退 en（对齐 Go bundle 默认 English）；未收录的键原样返回（对齐
//! Go LocalizeMessage 失败时回退 messageId 本身）。
//!
//! Go 代码里实际还会传少量 toml 未收录的键（UserNotFound/LoginFailed/
//! UserDisabled/LoginBanned/NoCaptchaRequired 等）——这些在 Go 侧同样走
//! "未收录回退键名" 路径，此处保持一致，不额外补译文。

/// Accept-Language 头 → 语言标签。
/// 对齐 Go global/i18n.go：直接把头值交给 bundle 匹配；这里取第一个
/// 分号前的主标签做前缀匹配（zh-CN→zh_CN、zh-TW→zh_TW、en→en…）。
pub fn lang_from_accept_language(header: &str) -> &'static str {
    let primary = header
        .split(',')
        .next()
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    match primary {
        l if l.starts_with("zh-TW") || l.starts_with("zh-Hant") => "zh_TW",
        l if l.starts_with("zh") => "zh_CN",
        "es" | "es-ES" | "es-MX" => "es",
        "fr" | "fr-FR" => "fr",
        "ko" | "ko-KR" => "ko",
        "ru" | "ru-RU" => "ru",
        _ => "en",
    }
}

/// (key, en, es, fr, ko, ru, zh_CN, zh_TW)
type Row = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

const TABLE: &[Row] = &[
    (
        "ParamsError",
        "Params validation failed.",
        "La validación de los parámetros falló.",
        "La validation des paramètres a échoué.",
        "매개변수 검증에 실패했습니다.",
        "Ошибка параметра.",
        "参数错误。",
        "參數驗證失敗。",
    ),
    (
        "OperationFailed",
        "the operation failed.",
        "La operación falló.",
        "l'opération a échoué.",
        "작업 실패.",
        "Операция не удалась.",
        "操作失败。",
        "操作失敗。",
    ),
    (
        "OperationSuccess",
        "the operation success.",
        "La operación fue exitosa.",
        "Opération réussie",
        "작업 성공.",
        "Операция успешна.",
        "操作成功。",
        "操作成功。",
    ),
    (
        "ItemExists",
        "Item already exists.",
        "El elemento ya existe.",
        "L'élément existe déjà.",
        "항목이 이미 존재합니다.",
        "Данные уже существуют.",
        "数据已存在。",
        "項目已存在。",
    ),
    (
        "ItemNotFound",
        "Item not found.",
        "El elemento no fue encontrado.",
        "Article introuvable.",
        "항목을 찾을 수 없습니다.",
        "Данные не найдены.",
        "数据不存在。",
        "找不到項目。",
    ),
    (
        "NoAccess",
        "No access.",
        "Sin acceso.",
        "Aucun d'access.",
        "접근할 수 없습니다.",
        "Нет доступа.",
        "无权限。",
        "無權限存取。",
    ),
    (
        "NeedLogin",
        "Please log in first.",
        "Por favor inicie sesión primero.",
        "Veuillez d'abord vous connecter.",
        "먼저 로그인해주세요.",
        "Пожалуйста, войдите в систему.",
        "请先登录。",
        "請先登入。",
    ),
    (
        "UsernameOrPasswordError",
        "Username or password error.",
        "Error de usuario o contraseña.",
        "Nom d'utilisateur ou de mot de passe incorrect.",
        "사용자 이름이나 비밀번호가 올바르지 않습니다.",
        "Неправильное имя пользователя или пароль.",
        "用户名或密码错误。",
        "使用者名稱或密碼錯誤。",
    ),
    (
        "SystemError",
        "System error.",
        "Error del sistema.",
        "Erreur system.",
        "시스템 오류.",
        "Системная ошибка.",
        "系统错误。",
        "系統錯誤。",
    ),
    (
        "ConfigNotFound",
        "Config not found.",
        "Configuración no encontrada.",
        "Configuration introuvable.",
        "구성이 존재하지 않습니다.",
        "Конфигурация не найдена.",
        "配置不存在。",
        "找不到設定。",
    ),
    (
        "OauthExpired",
        "Oauth expired, please try again.",
        "Oauth expirado, por favor intente nuevamente.",
        "Oauth a expiré, veuillez réessayer.",
        "인증이 만료되었습니다. 다시 승인해 주세요.",
        "Авторизация истекла, пожалуйста, авторизуйтесь снова.",
        "授权过期，请重新授权。",
        "OAuth 已過期，請重試。",
    ),
    (
        "OauthFailed",
        "Oauth failed.",
        "Oauth falló.",
        "Oauth a échoué.",
        "인증에 실패했습니다.",
        "Авторизация не удалась.",
        "授权失败。",
        "OAuth 失敗。",
    ),
    (
        "OauthHasBindOtherUser",
        "Oauth has bind other user.",
        "Oauth está vinculado a otro usuario.",
        "Oauth a lié un autre utilisateur.",
        "권한이 다른 사용자에게 바인딩되었습니다.",
        "Авторизация уже привязана к другому пользователю.",
        "授权已绑定其他用户。",
        "OAuth 已綁定其他使用者。",
    ),
    (
        "ParamIsEmpty",
        "{{.P0}} is empty.",
        "{{.P0}} está vacío.",
        "{{.P0}} est vide.",
        "{{.P0}} 비어 있습니다.",
        "{{.P0}} пуст.",
        "{{.P0}} 为空。",
        "{{.P0}} 為空。",
    ),
    (
        "BindFail",
        "Bind fail.",
        "Fallo al vincular.",
        "Échec de la liaison.",
        "바인딩 실패.",
        "Привязка не удалась.",
        "绑定失败。",
        "綁定失敗。",
    ),
    (
        "BindSuccess",
        "Bind success.",
        "Vinculación exitosa.",
        "Succès de la liaison.",
        "바인딩 성공.",
        "Привязка успешна.",
        "绑定成功。",
        "綁定成功。",
    ),
    (
        "OauthHasBeenSuccess",
        "Oauth has been success.",
        "Oauth fue exitoso.",
        "Oauth a été réussi avec Succès.",
        "인증이 완료되었습니다.",
        "Авторизация уже выполнена успешно.",
        "授权已成功。",
        "OAuth 已成功。",
    ),
    (
        "OauthSuccess",
        "Oauth success.",
        "Oauth exitoso.",
        "Oauh réussi avec succès.",
        "인증 성공.",
        "Авторизация успешна.",
        "授权成功。",
        "OAuth 成功。",
    ),
    (
        "OauthRegisterSuccess",
        "Oauth register success.",
        "Registro de Oauth exitoso.",
        "Succès de l'enregistrement Oauth.",
        "인증 등록이 완료되었습니다.",
        "Регистрация авторизации успешна.",
        "授权注册成功。",
        "OAuth 註冊成功。",
    ),
    (
        "OauthRegisterFailed",
        "Oauth register failed.",
        "Registro de Oauth falló.",
        "L'inscription Oauth a échoué.",
        "인증 등록에 실패했습니다.",
        "Ошибка регистрации авторизации.",
        "授权注册失败。",
        "OAuth 註冊失敗。",
    ),
    (
        "GetOauthTokenError",
        "Get oauth token error.",
        "Error al obtener el token de Oauth.",
        "Erreur de l'obtention du jeton oauth.",
        "인증 토큰을 획득하지 못했습니다.",
        "Не удалось получить токен авторизации.",
        "获取授权token失败。",
        "取得 OAuth 權杖錯誤。",
    ),
    (
        "GetOauthUserInfoError",
        "Get oauth user info error.",
        "Error al obtener la información del usuario de Oauth.",
        "Erreur d'obtention d'informations sur l'utilisateur oauth.",
        "인증된 사용자 정보를 획득하지 못했습니다.",
        "Не удалось получить информацию о пользователе авторизации.",
        "获取授权用户信息失败。",
        "取得 OAuth 使用者資訊錯誤。",
    ),
    (
        "DecodeOauthUserInfoError",
        "Decode oauth user info error.",
        "Error al decodificar la información del usuario de Oauth.",
        "Erreur de décodage des informations utilisateur oauth.",
        "인증된 사용자 정보를 구문 분석하지 못했습니다.",
        "Не удалось декодировать информацию о пользователе авторизации.",
        "解析授权用户信息失败。",
        "解析 OAuth 使用者資訊錯誤。",
    ),
    (
        "OldPasswordError",
        "Old password error.",
        "Error con la contraseña anterior.",
        "Ancien mot de passe incorrect.",
        "이전 비밀번호가 잘못되었습니다.",
        "Неправильный старый пароль.",
        "旧密码错误。",
        "舊密碼錯誤。",
    ),
    (
        "DefaultGroup",
        "Default Group",
        "Grupo predeterminado",
        "Groupe Défaut",
        "기본 그룹",
        "Группа по умолчанию",
        "默认组",
        "預設群組",
    ),
    (
        "ShareGroup",
        "Share Group",
        "Grupo compartido",
        "Groupe partagé",
        "공유 그룹",
        "Общая группа",
        "共享组",
        "共享群組",
    ),
    (
        "RegisterClosed",
        "Register closed.",
        "Registro cerrado.",
        "Inscription fermée.",
        "가입이 종료되었습니다.",
        "Регистрация закрыта.",
        "注册已关闭。",
        "註冊已關閉。",
    ),
    (
        "CaptchaRequired",
        "Captcha required.",
        "Captcha requerido.",
        "Captcha requis.",
        "Captcha가 필요합니다.",
        "Требуется капча.",
        "需要验证码。",
        "需要驗證碼。",
    ),
    (
        "CaptchaError",
        "Captcha error.",
        "Error de captcha.",
        "Erreur de captcha.",
        "Captcha 오류.",
        "Ошибка капчи.",
        "验证码错误。",
        "驗證碼錯誤。",
    ),
    (
        "PwdLoginDisabled",
        "Password login disabled.",
        "Inicio de sesión con contraseña deshabilitado.",
        "Connexion par mot de passe désactivée.",
        "비밀번호 로그인이 비활성화되었습니다.",
        "Вход по паролю отключен.",
        "密码登录已禁用。",
        "密碼登入已停用。",
    ),
    (
        "CannotShareToSelf",
        "Cannot share to self.",
        "No se puede compartir con uno mismo.",
        "Impossible de partager avec soi-même.",
        "자기 자신에게 공유할 수 없습니다.",
        "Нельзя поделиться с собой.",
        "不能共享给自己。",
        "無法分享給自己。",
    ),
    (
        "Banned",
        "Banned.",
        "Prohibido.",
        "Banni.",
        "금지됨.",
        "Заблокировано.",
        "已被封禁。",
        "已被禁用。",
    ),
    (
        "RegisterSuccessWaitAdminConfirm",
        "Register success, wait for admin confirm.",
        "Registro exitoso, espere la confirmación del administrador.",
        "Inscription réussie, veuillez attendre la confirmation de l'administrateur.",
        "가입 성공, 관리자 확인 대기 중.",
        "Регистрация прошла успешно, ожидайте подтверждения администратора.",
        "注册成功，请等待管理员审核。",
        "註冊成功，等待管理員確認。",
    ),
];

/// 翻译消息键。未收录的键返回键名本身（对齐 Go LocalizeMessage 失败回退）。
pub fn translate(lang: &str, key: &str) -> String {
    let idx: usize = match lang {
        "es" => 1,
        "fr" => 2,
        "ko" => 3,
        "ru" => 4,
        "zh_CN" => 5,
        "zh_TW" => 6,
        _ => 0, // en 及未知语言
    };
    for row in TABLE {
        let (k, en, es, fr, ko, ru, zh_cn, zh_tw) = *row;
        let msg = match idx {
            1 => es,
            2 => fr,
            3 => ko,
            4 => ru,
            5 => zh_cn,
            6 => zh_tw,
            _ => en,
        };
        if k == key {
            return msg.to_string();
        }
    }
    key.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_known_keys() {
        assert_eq!(translate("zh_CN", "ParamsError"), "参数错误。");
        assert_eq!(translate("en", "ParamsError"), "Params validation failed.");
        assert_eq!(translate("ko", "CaptchaError"), "Captcha 오류.");
        assert_eq!(translate("ru", "Banned"), "Заблокировано.");
        assert_eq!(translate("zh_TW", "NeedLogin"), "請先登入。");
        assert_eq!(translate("fr", "OauthSuccess"), "Oauh réussi avec succès.");
        assert_eq!(translate("es", "BindSuccess"), "Vinculación exitosa.");
    }

    #[test]
    fn unknown_key_falls_back_to_key() {
        assert_eq!(translate("zh_CN", "UserDisabled"), "UserDisabled");
        assert_eq!(translate("en", "Whatever"), "Whatever");
    }

    #[test]
    fn lang_detection() {
        assert_eq!(lang_from_accept_language("zh-CN,zh;q=0.9"), "zh_CN");
        assert_eq!(lang_from_accept_language("zh-TW"), "zh_TW");
        assert_eq!(lang_from_accept_language("en-US,en;q=0.5"), "en");
        assert_eq!(lang_from_accept_language("ko-KR"), "ko");
        assert_eq!(lang_from_accept_language(""), "en");
    }
}
