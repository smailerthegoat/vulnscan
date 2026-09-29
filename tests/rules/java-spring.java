package demo;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import java.sql.*;
import java.util.UUID;
import javax.servlet.http.*;
import org.apache.commons.io.FilenameUtils;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.HtmlUtils;

@RestController
public class ApiController {
    private JdbcTemplate jdbcTemplate;
    private RestTemplate rest;
    private Connection conn;

    @GetMapping("/users")
    public Object search(@RequestParam String name, @RequestParam(defaultValue = "id") String sort) throws Exception {
        Statement st = conn.createStatement();
        // ruleid: vulnscan.java.sql-injection
        st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
        // ruleid: vulnscan.java.sql-injection
        jdbcTemplate.queryForList("SELECT * FROM users ORDER BY " + sort);
        // ok: vulnscan.java.sql-injection
        jdbcTemplate.queryForList("SELECT * FROM users WHERE name = ?", name);
        return null;
    }

    @GetMapping("/users/{id}")
    public Object byId(@PathVariable Long id, @PathVariable("org") String org) throws Exception {
        // ok: vulnscan.java.sql-injection
        jdbcTemplate.queryForMap("SELECT * FROM users WHERE id = " + id);
        // ruleid: vulnscan.java.sql-injection
        jdbcTemplate.query("SELECT * FROM users WHERE org = '" + org + "'", (rs, i) -> rs.getString(1));
        return null;
    }

    @PostMapping("/ping")
    public String ping(@RequestBody PingRequest req) throws Exception {
        // ruleid: vulnscan.java.command-injection
        Runtime.getRuntime().exec("ping -c 1 " + req.getHost());
        // ruleid: vulnscan.java.command-injection
        new ProcessBuilder("sh", "-c", "nslookup " + req.getHost()).start();
        // ok: vulnscan.java.command-injection
        new ProcessBuilder("ping", "-c", "1", "example.com").start();
        return "ok";
    }

    @GetMapping("/files")
    public byte[] file(@RequestParam String name) throws Exception {
        // ruleid: vulnscan.java.path-traversal
        byte[] a = Files.readAllBytes(Paths.get("/srv/files", name));
        // ok: vulnscan.java.path-traversal
        byte[] b = Files.readAllBytes(Paths.get("/srv/files", FilenameUtils.getName(name)));
        // ruleid: vulnscan.java.path-traversal
        new FileInputStream(new File("/srv/files/" + name));
        return a;
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url, @RequestParam String user) throws Exception {
        // ruleid: vulnscan.java.ssrf
        rest.getForObject(url, String.class);
        // ruleid: vulnscan.java.ssrf
        new URL(url).openStream();
        // ok: vulnscan.java.ssrf
        rest.getForObject("https://api.example.com/users/" + user, String.class);
        return "ok";
    }

    @GetMapping("/calc")
    public Object calc(@RequestParam String expr) {
        // ruleid: vulnscan.java.expression-injection
        return new SpelExpressionParser().parseExpression(expr).getValue();
    }

    @PostMapping("/import")
    public Object load(HttpServletRequest request) throws Exception {
        // ruleid: vulnscan.java.unsafe-deserialization
        ObjectInputStream in = new ObjectInputStream(request.getInputStream());
        return in.readObject();
    }

    @GetMapping("/login")
    public void login(@RequestParam String next, HttpServletResponse response) throws Exception {
        // ruleid: vulnscan.java.open-redirect
        response.sendRedirect(next);
    }

    public void notAHandler(String name) throws Exception {
        // ok: vulnscan.java.sql-injection
        conn.createStatement().executeQuery("SELECT * FROM t WHERE n = '" + name + "'");
    }
}

class LegacyServlet extends HttpServlet {
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String q = request.getParameter("q");
        // ruleid: vulnscan.java.xss
        response.getWriter().println("<p>Results for " + q + "</p>");
        // ok: vulnscan.java.xss
        response.getWriter().println("<p>Results for " + HtmlUtils.htmlEscape(q) + "</p>");
    }
}

@Controller
class PageController {
    @GetMapping("/doc")
    public String doc(@RequestParam String section) {
        // ruleid: vulnscan.java.view-name-injection
        return "docs/" + section;
    }

    @GetMapping("/home")
    public String home(@RequestParam String next) {
        // ruleid: vulnscan.java.open-redirect
        return "redirect:" + next;
    }
}
