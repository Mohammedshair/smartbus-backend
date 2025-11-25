package com.example.smartbus;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = {"*","http://127.0.0.1:5500"})
public class ApiController {

    private final Map<String, Student> students = new ConcurrentHashMap<>();
    private final QrService qrService;

    private final Path qrsDir = Paths.get("src/main/resources/static/qr");
    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    private static final byte[] SECRET =
            Optional.ofNullable(System.getenv("APP_SECRET"))
            .map(String::getBytes)
            .orElse("ReplaceThisWithAStrongSecretKey123!".getBytes());

    private static final String HMAC = "HmacSHA256";

    @Autowired
    public ApiController(QrService qrService) {
        this.qrService = qrService;

        try {
            if (Files.notExists(qrsDir)) Files.createDirectories(qrsDir);
        } catch (IOException ignored) {}
    }

    // ============================================================
    // ADD STUDENT -> returns token
    // ============================================================
    @PostMapping("/add-student")
    public ResponseEntity<?> addStudent(@RequestBody AddStudentRequest req) throws Exception {

        if (req.usn == null || req.usn.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "usn-required"));
        }
        if (req.expires == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "expiry-required"));
        }

        LocalDate expiry;
        try {
            expiry = LocalDate.parse(req.expires);
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid-date"));
        }

        Student s = new Student(
                req.usn.trim(),
                req.name == null ? "" : req.name.trim(),
                req.route == null ? "" : req.route.trim(),
                expiry
        );

        students.put(s.usn, s);

        String issued = LocalDate.now().toString();

        String payload = String.join("|",
                s.usn,
                s.name,
                s.route,
                s.expires.toString(),
                issued
        );

        String token = makeToken(payload);

        return ResponseEntity.ok(Map.of(
                "token", token,
                "payload", payload
        ));
    }

    // ============================================================
    // VERIFY TOKEN
    // ============================================================
    @PostMapping("/verify")
    public ResponseEntity<ScanResponse> verify(@RequestBody ScanRequest req) throws Exception {

        ScanResponse resp = new ScanResponse();

        String token = req.token;
        String payload;

        try {
            payload = decodeAndVerify(token);
        } catch (TokenException e) {
            resp.result = "NO_ENTRY";
            resp.reason = e.getMessage();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }

        String[] p = payload.split("\\|", -1);
        if (p.length < 5) {
            resp.result = "NO_ENTRY";
            resp.reason = "invalid-payload-format";
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }

        String usn = p[0];
        String route = p[2];
        String expires = p[3];

        Student s = students.get(usn);

        if (s == null) {
            resp.result = "NO_ENTRY";
            resp.reason = "usn-not-found";
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(resp);
        }

        resp.usn = s.usn;
        resp.name = s.name;

        LocalDate expiry;
        try {
            expiry = LocalDate.parse(expires);
        } catch (Exception e) {
            resp.result = "DENY";
            resp.reason = "invalid-expiry-in-token";
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(resp);
        }

        if (expiry.isBefore(LocalDate.now())) {
            resp.result = "DENY";
            resp.reason = "expired";
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(resp);
        }

        if (!route.equalsIgnoreCase(s.route)) {
            resp.result = "DENY";
            resp.reason = "route-mismatch";
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(resp);
        }

        resp.result = "ALLOW";
        resp.reason = "ok";
        return ResponseEntity.ok(resp);
    }


    // ============================================================
    // GET QR PNG → /api/qr/{usn}
    // ============================================================
    @GetMapping(value = "/qr/{usn}", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> getQr(@PathVariable String usn) throws Exception {

        Student s = students.get(usn);
        if (s == null) return ResponseEntity.notFound().build();

        String payload = String.join("|",
                s.usn,
                s.name,
                s.route,
                s.expires.toString(),
                LocalDate.now().toString()
        );

        String token = makeToken(payload);

        Path file = qrService.getQrPathForUsn(s.usn);

        if (Files.exists(file)) {
            return ResponseEntity.ok(Files.readAllBytes(file));
        }

        Object lock = locks.computeIfAbsent(usn, k -> new Object());

        synchronized (lock) {

            if (Files.exists(file)) {
                return ResponseEntity.ok(Files.readAllBytes(file));
            }

            byte[] png = qrService.generateAndSaveIfMissing(token, qrService.fileNameForUsn(usn));
            return ResponseEntity.ok(png);
        }
    }

    // ============================================================
    // /api/qr-list
    // ============================================================
    @GetMapping("/qr-list")
    public ResponseEntity<List<String>> listQr() {
        try {
            if (Files.notExists(qrsDir)) return ResponseEntity.ok(List.of());

            List<String> urls = Files.list(qrsDir)
                    .filter(Files::isRegularFile)
                    .map(p -> "/qr/" + p.getFileName().toString())
                    .collect(Collectors.toList());

            return ResponseEntity.ok(urls);

        } catch (Exception e) {
            return ResponseEntity.ok(List.of());
        }
    }

    // ============================================================
    // TOKEN TOOLS
    // ============================================================

    private String makeToken(String payload) throws Exception {

        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();

        byte[] data = payload.getBytes(StandardCharsets.UTF_8);

        String payloadB64 = enc.encodeToString(data);

        byte[] signature = hmac(data);
        String sigB64 = enc.encodeToString(signature);

        return payloadB64 + "." + sigB64;
    }

    private String decodeAndVerify(String token) throws Exception {

        if (!token.contains(".")) throw new TokenException("invalid-token-format");

        String[] parts = token.split("\\.", 2);

        Base64.Decoder dec = Base64.getUrlDecoder();

        byte[] payloadBytes = dec.decode(parts[0]);
        byte[] sigBytes = dec.decode(parts[1]);

        byte[] expected = hmac(payloadBytes);

        if (!MessageDigest.isEqual(sigBytes, expected))
            throw new TokenException("invalid-signature");

        return new String(payloadBytes, StandardCharsets.UTF_8);
    }

    private byte[] hmac(byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(SECRET, HMAC));
        return mac.doFinal(data);
    }

    static class TokenException extends Exception {
        public TokenException(String msg) { super(msg); }
    }
}
