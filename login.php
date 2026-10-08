<?php
declare(strict_types=1);
require __DIR__ . '/config.php';

session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
session_start();

if (!empty($_SESSION['user'])) {
    header('Location: index.php');
    exit;
}
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

/** Ищет аккаунт по логину через Supabase Data API. */
function find_account(string $login): ?array
{
    $url = SUPABASE_URL . '/rest/v1/accounts'
         . '?select=id,name,passw,rusname,surname,othername,job_invite&limit=1'
         . '&name=eq.' . rawurlencode($login);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 8,
        CURLOPT_HTTPHEADER     => [
            'apikey: ' . SUPABASE_KEY,
            'Authorization: Bearer ' . SUPABASE_KEY,
            'Accept: application/json',
        ],
    ]);
    $body = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false || $code !== 200) {
        throw new RuntimeException('Supabase HTTP ' . $code);
    }
    $rows = json_decode($body, true);
    return is_array($rows) && isset($rows[0]) ? $rows[0] : null;
}

/** Работает и с числом/текстом, и с хешем password_hash() (когда перейдёте на него). */
function check_password($stored, string $input): bool
{
    if ($stored === null) {
        return false;
    }
    $stored = (string) $stored;
    if (str_starts_with($stored, '$2y$') || str_starts_with($stored, '$argon2')) {
        return password_verify($input, $stored);
    }
    return hash_equals($stored, $input);
}

function initial(?string $s): string
{
    $s = trim((string) $s);
    return $s === '' ? '' : mb_strtoupper(mb_substr($s, 0, 1)) . '.';
}

$error = '';
$login = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login = trim((string) ($_POST['login'] ?? ''));
    $pass  = (string) ($_POST['password'] ?? '');

    if (!hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
        $error = 'Сессия устарела, обновите страницу.';
    } elseif (time() < ($_SESSION['lock'] ?? 0)) {
        $error = 'Слишком много попыток. Повторите через несколько минут.';
    } elseif ($login === '' || $pass === '') {
        $error = 'Введите логин и пароль.';
    } else {
        try {
            $row = find_account($login);
            if ($row && check_password($row['passw'], $pass)) {
                session_regenerate_id(true);
                $_SESSION['user'] = [
                    'id'   => $row['id'],
                    'name' => $row['name'],
                    'fio'  => trim($row['surname'] . ' ' . initial($row['rusname']) . initial($row['othername'])),
                    'job'  => (string) ($row['job_invite'] ?? ''),
                ];
                $_SESSION['fails'] = 0;
                header('Location: index.php');
                exit;
            }
            $error = 'Неверный логин или пароль.';
            $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1;
            if ($_SESSION['fails'] >= 5) {
                $_SESSION['lock']  = time() + 300;
                $_SESSION['fails'] = 0;
            }
            usleep(400000);
        } catch (Throwable $e) {
            error_log($e->getMessage());
            $error = 'Сервис временно недоступен. Попробуйте позже.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Авторизация — ООО «Регион-проект»</title>
  <link rel="stylesheet" href="login.css">
</head>
<body>

  <div class="bg">
    <span style="background-image:url('fon1.png')"></span>
    <span style="background-image:url('fon2.png')"></span>
    <span style="background-image:url('fon3.png')"></span>
  </div>

  <aside class="panel">
    <img class="panel__logo" src="logo.png" alt="Регион-проект">
    <h1>Авторизация</h1>

    <?php if ($error !== ''): ?>
      <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="post" autocomplete="on">
      <input type="hidden" name="csrf" value="<?= htmlspecialchars($_SESSION['csrf']) ?>">

      <label for="login">Логин</label>
      <input id="login" name="login" type="text" autocomplete="username"
             value="<?= htmlspecialchars($login) ?>" required autofocus>

      <label for="password">Пароль</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required>

      <button type="submit">Продолжить</button>
    </form>
  </aside>

</body>
</html>
