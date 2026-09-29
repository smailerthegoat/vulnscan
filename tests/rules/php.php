<?php
$name = $_GET['name'];
$id = $_GET['id'];

// ruleid: vulnscan.php.sql-injection
$r = mysqli_query($conn, "SELECT * FROM users WHERE name = '$name'");
// ruleid: vulnscan.php.sql-injection
$pdo->query("SELECT * FROM users WHERE id = " . $_POST['id']);
// ok: vulnscan.php.sql-injection
$pdo->query("SELECT * FROM users WHERE id = " . intval($id));
// ok: vulnscan.php.sql-injection
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = ?");
// ok: vulnscan.php.sql-injection
$r = mysqli_query($conn, "SELECT * FROM users WHERE name = '" . mysqli_real_escape_string($conn, $name) . "'");

// ruleid: vulnscan.php.command-injection
system("ping -c 1 " . $_GET['host']);
// ok: vulnscan.php.command-injection
system("ping -c 1 " . escapeshellarg($_GET['host']));
// ruleid: vulnscan.php.command-injection
$out = `nslookup {$_REQUEST['host']}`;

// ruleid: vulnscan.php.code-injection
eval('return ' . $_POST['expr'] . ';');

// ruleid: vulnscan.php.file-inclusion
include $_GET['page'] . '.php';
// ok: vulnscan.php.file-inclusion
include 'pages/' . basename($_GET['page']) . '.php';

// ruleid: vulnscan.php.path-traversal
readfile('/var/www/uploads/' . $_GET['file']);
// ok: vulnscan.php.path-traversal
readfile('/var/www/uploads/' . basename($_GET['file']));

// ruleid: vulnscan.php.ssrf
$ch = curl_init($_GET['url']);
// ok: vulnscan.php.ssrf
$ch2 = curl_init("https://api.example.com/items/" . $id);

// ruleid: vulnscan.php.open-redirect
header("Location: " . $_GET['next']);

// ruleid: vulnscan.php.xss
echo "<p>Hello " . $name . "</p>";
// ok: vulnscan.php.xss
echo "<p>Hello " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "</p>";
// ok: vulnscan.php.xss
echo "<p>Item " . (int)$id . "</p>";

// ruleid: vulnscan.php.unsafe-deserialization
$prefs = unserialize($_COOKIE['prefs']);
// ok: vulnscan.php.unsafe-deserialization
$prefs2 = unserialize($_COOKIE['prefs'], ['allowed_classes' => false]);

$xml = file_get_contents('php://input');
// ruleid: vulnscan.php.xxe
$doc = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT);
// ok: vulnscan.php.xxe
$doc2 = simplexml_load_string($xml);

// ruleid: vulnscan.php.variable-extraction
extract($_POST);

class ProfileController extends Controller
{
    public function search(Request $request)
    {
        // ruleid: vulnscan.php.sql-injection
        return DB::select("SELECT * FROM users WHERE name = '" . $request->input('name') . "'");
    }

    public function sorted(Request $request)
    {
        // ruleid: vulnscan.php.sql-injection
        return User::query()->orderByRaw($request->query('sort'))->get();
    }

    public function update(Request $request, User $user)
    {
        // ruleid: vulnscan.php.mass-assignment
        $user->update($request->all());
        // ruleid: vulnscan.php.open-redirect
        return redirect()->away($request->input('return_to'));
    }

    public function avatar(Request $request)
    {
        // ruleid: vulnscan.php.path-traversal
        return response()->download(storage_path('avatars/' . $request->route('file')));
    }
}
