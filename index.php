<?php
/*  AI-Blog
    https://github.com/admxn-coder/ai-blog
    License: MIT
*/

session_start();
header('Content-Type: text/html; charset=utf-8');

// 安全设置
define('DATA_DIR', __DIR__ . '/data');
define('POSTS_DIR', DATA_DIR . '/posts');
define('CONFIG_FILE', DATA_DIR . '/config.php');
define('CSRF_KEY', 'csrf_token');
define('CACHE_DIR', DATA_DIR . '/cache');
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOGIN_LOCKOUT_TIME', 1800); // 30分钟
define('CSRF_TOKEN_LIFETIME', 3600); // 1小时
define('POSTS_PER_PAGE', 10);

// 初始化检测
if (!is_dir(DATA_DIR)) mkdir(DATA_DIR, 0755, true);
if (!is_dir(POSTS_DIR)) mkdir(POSTS_DIR, 0755, true);
if (!is_dir(CACHE_DIR)) mkdir(CACHE_DIR, 0755, true);

// 读取配置
$config = [
    'site_name' => '',
    'admin_user' => '',
    'admin_pass_hash' => '',
    'login_path' => '',
];
if (file_exists(CONFIG_FILE)) {
    include CONFIG_FILE;
    if (isset($cfg) && is_array($cfg)) $config = array_merge($config, $cfg);
}

// 安装流程 - 添加已安装检查
$act = $_GET['a'] ?? '';
if (!file_exists(CONFIG_FILE) || $act === 'install') {
    if (file_exists(CONFIG_FILE)) {
        header('Location: ?'); exit; // 已安装则跳转
    }
    
    if (version_compare(PHP_VERSION, '7.2.0', '<')) {
        die('需要 PHP 7.2.0 或更高版本');
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['site_name'], $_POST['admin_user'], $_POST['admin_pass'])) {
        $site_name = trim($_POST['site_name']);
        $admin_user = trim($_POST['admin_user']);
        $admin_pass = $_POST['admin_pass'];
        $login_path = trim($_POST['login_path'] ?? '');
        
        if ($site_name === '' || $admin_user === '' || $admin_pass === '') {
            $msg = '所有字段均不能为空';
        } else {
            if ($login_path === '') $login_path = bin2hex(random_bytes(8));
            $login_path = preg_replace('/[^a-zA-Z0-9_-]/', '', $login_path);
            if ($login_path === '') $login_path = bin2hex(random_bytes(8));
            
            $hash = password_hash($admin_pass, PASSWORD_DEFAULT);
            $conf = [
                'site_name' => $site_name,
                'admin_user' => $admin_user,
                'admin_pass_hash' => $hash,
                'login_path' => $login_path
            ];
            $php = "<?php\n\$cfg = " . var_export($conf, true) . ";";
            file_put_contents(CONFIG_FILE, $php);
            header('Location: ?a=' . urlencode($login_path)); // 跳转到登录页面
            exit;
        }
    }
    ?><!DOCTYPE html>
    <html><head><meta charset="utf-8"><title>初始化博客</title><meta name="viewport" content="width=device-width,initial-scale=1"><style>*,::after,::before{margin:0;box-sizing:border-box;letter-spacing:.5px}body{max-width:400px;margin:2rem auto;padding:1rem;font:16px/1.6 Georgia,serif;}form{margin-top:2rem;}form input,form textarea,form button,input:focus,textarea:focus,button:focus{width:100%;font:inherit;padding:.5em;margin:.5em 0;border: none;border:1px solid #ccc;}</style></head><body>
    <h2>初始化博客</h2>
    <form method="post">
        <input name="site_name" placeholder="站点名称" value="<?php echo htmlspecialchars($config['site_name']);?>" required>
        <input name="admin_user" placeholder="管理员用户名" value="<?php echo htmlspecialchars($config['admin_user']);?>" required>
        <input name="admin_pass" type="password" placeholder="管理员密码" required>
        <input name="login_path" placeholder="登录入口路径(如: admin-login)" value="<?php echo htmlspecialchars($config['login_path']);?>" maxlength="32" pattern="[a-zA-Z0-9_-]{4,32}" title="4-32位字母数字或-_，留空自动生成" autocomplete="off">
        <button type="submit">保存并进入博客</button>
        <?php if(!empty($msg)) echo '<div style="color:red">' . htmlspecialchars($msg) . '</div>'; ?>
    </form>
    <div style="margin-top:2em;color:#888;font-size:0.9em">登录入口建议自定义，留空则自动生成随机安全路径。</div>
    </body></html><?php exit; }


// 定义常量
define('ADMIN_USER', $config['admin_user']);
define('ADMIN_PASS_HASH', $config['admin_pass_hash']);
define('SITE_NAME', $config['site_name']);
define('LOGIN_PATH', $config['login_path']);

// ========== 工具函数 ==========
function get_csrf_token() {
    // 检查令牌是否存在或已过期
    if (empty($_SESSION[CSRF_KEY]) || 
        (isset($_SESSION[CSRF_KEY . '_expire']) && $_SESSION[CSRF_KEY . '_expire'] < time())) {
        $_SESSION[CSRF_KEY] = bin2hex(random_bytes(32));
        $_SESSION[CSRF_KEY . '_expire'] = time() + CSRF_TOKEN_LIFETIME;
    }
    return $_SESSION[CSRF_KEY];
}

function check_csrf_token() {
    $token = $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
    return is_login() && $token && hash_equals($_SESSION[CSRF_KEY] ?? '', $token);
}

function is_login() {
    return !empty($_SESSION['admin']);
}

function sanitize_id($id) {
    return preg_replace('/[^a-zA-Z0-9_-]/', '', $id);
}

function validate_file_path($file) {
    $realPostsDir = realpath(POSTS_DIR) . DIRECTORY_SEPARATOR;
    $realFilePath = realpath(dirname($file)) . DIRECTORY_SEPARATOR . basename($file);
    return $realFilePath !== false && strpos($realFilePath, $realPostsDir) === 0;
}

function save_post($id, $title, $content, $tags, $time, $public) {
    $id = sanitize_id($id);
    if(empty($id)) return false;
    $metaFile = POSTS_DIR . "/$id.meta.json";
    $contentFile = POSTS_DIR . "/$id.md";
    if (!validate_file_path($metaFile) || !validate_file_path($contentFile)) {
        return false;
    }
    if(!is_writable(POSTS_DIR)) return false;
    $meta = [
        'id' => $id,
        'title' => $title,
        'tags' => array_filter(array_map('trim', $tags)),
        'time' => $time,
        'public' => $public ? 1 : 0
    ];
    // 写入元数据
    if(file_put_contents($metaFile, json_encode($meta, JSON_UNESCAPED_UNICODE)) === false) {
        return false;
    }
    // 写入内容
    if(file_put_contents($contentFile, $content) === false) {
        @unlink($metaFile);
        return false;
    }
    clear_cache();
    return true;
}

function load_post($id) {
    $id = sanitize_id($id);
    $metaFile = POSTS_DIR . "/$id.meta.json";
    $contentFile = POSTS_DIR . "/$id.md";
    if (!validate_file_path($metaFile) || !validate_file_path($contentFile)) {
        return null;
    }
    $meta = @json_decode(@file_get_contents($metaFile), true);
    if (!$meta) return null;
    $content = @file_get_contents($contentFile);
    if ($content === false) return null;
    $meta['content'] = $content;
    return $meta;
}

function list_posts($forceRefresh = false) {
    $cacheFile = CACHE_DIR . '/posts_cache.json';
    $cacheTime = 3600; // 缓存1小时
    // 检查缓存是否有效
    if (!$forceRefresh && file_exists($cacheFile) && (time() - filemtime($cacheFile) < $cacheTime)) {
        $content = file_get_contents($cacheFile);
        return json_decode($content, true) ?: [];
    }
    // 生成新缓存
    $files = glob(POSTS_DIR . '/*.meta.json');
    $posts = [];
    foreach ($files as $f) {
        if (!validate_file_path($f)) continue;
        $meta = json_decode(file_get_contents($f), true);
        $id = $meta['id'] ?? basename($f, '.meta.json');
        $meta['id'] = $id;
        $meta['content'] = '';
        $posts[] = $meta;
    }
    usort($posts, function($a, $b){ return ($b['time']??0) - ($a['time']??0); });
    file_put_contents($cacheFile, json_encode($posts, JSON_UNESCAPED_UNICODE));
    return $posts;
}

function clear_cache() {
    $cacheFile = CACHE_DIR . '/posts_cache.json';
    if (file_exists($cacheFile)) @unlink($cacheFile);
}

function all_tags($posts) {
    $tags = [];
    foreach ($posts as $p) {
        foreach ($p['tags'] as $t) {
            if($t) $tags[$t] = ($tags[$t]??0)+1;
        }
    }
    arsort($tags);
    return array_keys($tags);
}

function filter_posts($posts, $tag = '', $q = '') {
    return array_values(array_filter($posts, function($p) use($tag, $q) {
        $ok = true;
        if ($tag) $ok = in_array($tag, $p['tags']);
        if ($q) $ok = $ok && (stripos($p['title'],$q)!==false || stripos(($p['content']??''),$q)!==false);
        return $ok && ($p['public']??1);
    }));
}

// 分页处理
function paginate_posts($posts, $page = 1) {
    $total = count($posts);
    $pages = max(1, ceil($total / POSTS_PER_PAGE));
    $page = max(1, min($page, $pages));
    $offset = ($page - 1) * POSTS_PER_PAGE;
    
    return [
        'posts' => array_slice($posts, $offset, POSTS_PER_PAGE),
        'page' => $page,
        'pages' => $pages,
        'total' => $total
    ];
}

// 登录尝试限制
function track_login_attempts($success = false) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $key = 'login_attempts_' . $ip;
    
    if ($success) {
        // 登录成功，重置计数器
        unset($_SESSION[$key]);
        return true;
    }
    
    // 初始化或增加尝试次数
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['count' => 1, 'first_attempt' => time()];
    } else {
        $_SESSION[$key]['count']++;
    }
    
    // 检查是否超出限制
    $attempts = $_SESSION[$key];
    if ($attempts['count'] > MAX_LOGIN_ATTEMPTS) {
        $elapsed = time() - $attempts['first_attempt'];
        if ($elapsed < LOGIN_LOCKOUT_TIME) {
            $remaining = LOGIN_LOCKOUT_TIME - $elapsed;
            return "登录尝试次数过多，请在" . floor($remaining / 60) . "分钟后再试";
        } else {
            // 锁定时间已过，重置计数器
            $_SESSION[$key] = ['count' => 1, 'first_attempt' => time()];
        }
    }
    
    return true;
}

// ========== 路由处理 ==========
$act = $_GET['a'] ?? '';
$id = $_GET['id'] ?? '';
$tag = $_GET['tag'] ?? '';
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;


// 严格的登录路径验证
$is_valid_login_route = ($act === LOGIN_PATH);
if ($is_valid_login_route) {
    $act = 'login';
}

// 拒绝直接访问?a=login，除非login就是配置的登录路径
if (isset($_GET['a']) && $_GET['a'] === 'login' && LOGIN_PATH !== 'login') {
    header('Location: ?');
    exit;
}

// ========== 登录/登出 ==========
if ($act === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!$is_valid_login_route) {
        header('Location: ?');
        exit;
    }
    
    // 检查登录尝试次数
    $attemptResult = track_login_attempts();
    if ($attemptResult !== true) {
        $msg = $attemptResult;
    } else {
        if ($_POST['user'] === ADMIN_USER && password_verify($_POST['pass'], ADMIN_PASS_HASH)) {
            track_login_attempts(true); // 重置尝试计数器
            $_SESSION['admin'] = 1;
            get_csrf_token(); // 生成新的CSRF令牌
            header('Location: ?'); exit;
        }
        $msg = '用户名或密码错误';
    }
}

if ($act === 'logout') {
    session_destroy(); 
    header('Location: ?'); 
    exit;
}

// ========== 文章操作 ==========
if ($act === 'save' && is_login() && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!check_csrf_token()) die('CSRF校验失败');
    
    $title = trim($_POST['title'] ?? '');
    $content = trim($_POST['content'] ?? '');
    $tags = array_filter(array_map('trim', explode(',', $_POST['tags'] ?? '')));
    $public = isset($_POST['public']) ? 1 : 0;
    
    $editId = $_POST['id'] ?? '';
    if ($editId) {
        $existingPost = load_post($editId);
        $time = $_POST['time'] ? strtotime($_POST['time']) : ($existingPost['time'] ?? time());
    } else {
        $time = $_POST['time'] ? strtotime($_POST['time']) : time();
    }
    
    if ($title === '' || $content === '') die('标题和内容不能为空');
    
    $id = $editId ? sanitize_id($editId) : uniqid();
    if (!save_post($id, $title, $content, $tags, $time, $public)) {
        die('保存文章失败：请检查data/posts目录是否存在且可写');
    }
    header('Location: ?id='.$id); 
    exit;
}

if ($act === 'delete' && is_login() && $id) {
    if (!check_csrf_token()) die('CSRF校验失败');
    
    $id = sanitize_id($id);
    $metaFile = POSTS_DIR . "/$id.meta.json";
    $contentFile = POSTS_DIR . "/$id.md";
    
    if (validate_file_path($metaFile)) @unlink($metaFile);
    if (validate_file_path($contentFile)) @unlink($contentFile);
    
    clear_cache(); // 清除缓存
    header('Location: ?'); 
    exit;
}

// ========== 页面输出 ==========
$posts = list_posts();
$all_tags = all_tags($posts);
$show = $id ? load_post($id) : null;
$filtered_posts = $tag ? filter_posts($posts, $tag, '') : array_filter($posts, fn($p)=>($p['public']??1)||is_login());
$paged = paginate_posts($filtered_posts, $page);
?>


<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<?php
$site_name = htmlspecialchars(SITE_NAME);
$title = $show ? htmlspecialchars($show['title']) . ' - ' . $site_name : $site_name;
?>
<title><?php echo $title; ?></title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="generator" content="ai-blog">
<meta name="license" content="MIT License">
<style>
*,::after,::before{margin:0;box-sizing:border-box;letter-spacing:.5px}
body { font-family: system-ui, sans-serif; line-height: 1.6;}
footer,header,main{max-width:580px;margin:3rem auto;padding:0 1rem}
a{text-decoration:none;color:#222}
nav{margin-bottom:4rem;display:flex;gap:1rem}
nav a{font-size:14px}
h1{font-size:1.5rem;margin-bottom:1.5rem}
.post{display:flex;align-items:flex-start;margin-bottom:1rem}
.post time{width:120px}
.post a{flex:1}
.tags{display:flex;gap:2rem;flex-wrap:wrap}
.links,footer{font-size:13px;margin-top:3rem}
.links a{margin-right:20px}
button:focus,form button,form input,form textarea,input:focus,textarea:focus{width:100%;font:inherit;padding:.5em;margin:.5em 0;border:none;border:1px solid #ccc}
.flxw{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center}
.flxw input{width:auto}
button{cursor:pointer}
.pagination a{padding:.4rem;text-decoration:none}
.pagination a.active{font-weight:700;text-decoration:underline}
@media (max-width:600px){.post{flex-direction:column}
}
</style>
</head>
<body>
<header>
    <nav>
        <a href="/">博客</a>
        <a href="?a=tags">标签</a>
        <?php if(is_login()): ?>
        <a href="?a=edit">写文章</a> 
        <a href="?a=logout" onclick="return confirm('确定注销登录？别忘记入口：?a=<?php echo htmlspecialchars(LOGIN_PATH); ?>')">注销</a>
        <?php endif; ?>
    </nav>
    <?php if (empty($act) && !$show): ?>
    <h1><a href="?"><?php echo htmlspecialchars(SITE_NAME); ?></a></h1>
    <p>
        我不是管理员，因为我连自己都管不了
    </p>
    <?php endif; ?>
</header>

<main>
<?php if($act==='tags'): ?>
  <h1>内容标签</h1>
    <div class="tags">
    <?php if(empty($all_tags)): ?>暂无标签<?php else: ?>
    <?php foreach($all_tags as $t): ?>
      <a href="?tag=<?php echo urlencode($t);?>">
        #<?php echo htmlspecialchars($t);?>
        <sup><?php 
          // 统计数量
          $count = 0;
          foreach($posts as $p){ if(in_array($t,$p['tags'])) $count++; }
          echo $count;
        ?></sup>
      </a>
    <?php endforeach; ?>
    <?php endif; ?>
    </div>

<?php elseif($act==='login'): ?>
  <h2>登录</h2>
  <form method="post">
    <input name="user" placeholder="用户名" required>
    <input name="pass" type="password" placeholder="密码" required>
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(get_csrf_token());?>">
    <button type="submit">登录</button>
    <?php if(!empty($msg)) echo '<div style="color:red">' . htmlspecialchars($msg) . '</div>'; ?>
  </form>
<?php elseif($act==='edit' && is_login()): 
    $edit = $id ? load_post($id) : ['id'=>'','title'=>'','content'=>'','tags'=>[],'time'=>time(),'public'=>1]; ?>
    <h2><?php echo $id?'编辑文章':'写文章';?></h2>
    <form method="post" action="?a=save">
        <input name="title" value="<?php echo htmlspecialchars($edit['title']);?>" placeholder="标题" required>
        <textarea name="content" rows="12" placeholder="内容 (Markdown)"><?php echo htmlspecialchars($edit['content']);?></textarea>
        <input name="tags" value="<?php echo htmlspecialchars(implode(',', $edit['tags']));?>" placeholder="标签 (逗号分隔)">
        <div class="flxw">
        <input type="datetime-local" name="time" value="<?php echo date('Y-m-d\\TH:i', $edit['time']);?>">
        <label><input type="checkbox" name="public" value="1" <?php if(!isset($edit['public'])||$edit['public'])echo 'checked';?>> 公开</label>
        </div>
        <input type="hidden" name="id" value="<?php echo htmlspecialchars($edit['id']);?>">
        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars(get_csrf_token());?>">
        <button type="submit">保存</button>
    </form>

<?php elseif($show): ?>
    <h1><?php echo htmlspecialchars($show['title']);?></h1>
    <time><?php echo date('M j, Y', $show['time']);?></time>
    <?php if(empty($show['public'])): ?>未公开<?php endif; ?>

    <article id="md-content" itemprop="articleBody">
        <?php
        echo nl2br(htmlspecialchars($show['content'] ?? ''));
        ?>
    </article>

    <div class="links">
        <?php foreach($show['tags'] as $t): ?><a href="?tag=<?php echo urlencode($t);?>">#<?php echo htmlspecialchars($t);?></a><?php endforeach; ?>
    </div>
    <br>
    <a href="?">← 返回首页</a>
    <?php if(is_login()): ?>
    <a href="?a=edit&id=<?php echo $show['id'];?>">编辑</a>
    <a href="?a=delete&id=<?php echo $show['id'];?>&csrf_token=<?php echo htmlspecialchars(get_csrf_token());?>" onclick="return confirm('确定删除？')">删除</a>
    <?php endif; ?>

<?php else: ?>
    <?php foreach($paged['posts'] as $p): ?>
    <div class="post">
        <time><?php echo date('M j, Y', $p['time']); ?></time>
        <a href="?id=<?php echo $p['id'];?>"><?php echo htmlspecialchars($p['title']);?></a>
    </div>
    <?php endforeach; ?>

  <!-- 分页控件 -->
  <?php if($paged['pages'] > 1): ?>
  <div class="pagination">
    <?php for($i=1; $i<=$paged['pages']; $i++): ?>
      <?php $params = $tag ? "tag=$tag&page=$i" : "page=$i"; ?>
      <a href="?<?php echo $params; ?>" class="<?php echo $i == $paged['page'] ? 'active' : ''; ?>">
        <?php echo $i; ?>
      </a>
    <?php endfor; ?>
  </div>
  <?php endif; ?>


    <div class="links">
        <a href="https://github.com/admxn-coder/">↗ github</a>
        <a href="https://github.com/admxn-coder/ai-blog">↗ 查看源码</a>
    </div>

<?php endif; ?>
</main>

<footer>
    © 2025 <?php echo htmlspecialchars(SITE_NAME); ?>. All rights reserved.
</footer>

</body>
</html>
    
