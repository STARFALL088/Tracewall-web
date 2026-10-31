package tracewall.desktop;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ChatBotTest {

    private final Stats stats = new Stats();
    private final EventLog events = new EventLog(10);

    private static OllamaClient client(String url) {
        return new OllamaClient(url, Duration.ofSeconds(2), Duration.ofSeconds(5), Duration.ofSeconds(5));
    }

    @Test
    void retrievalPicksTheSectionThatMentionsTheTerm() {
        ChatBot bot = ChatBot.docsOnly(stats, events);
        ChatBot.Reply reply = bot.answer("What does servfail mean?");
        assertEquals("docs", reply.source());
        assertTrue(reply.text().startsWith("Stat card meanings"), reply.text());
    }

    @Test
    void overrideQuestionFindsTheOverrideSection() {
        ChatBot.Reply reply = ChatBot.docsOnly(stats, events).answer("how do I override a domain");
        assertTrue(reply.text().contains("Mark safe"), reply.text());
    }

    @Test
    void allowAQuestionFindsTheOverrideSection() {
        ChatBot.Reply reply = ChatBot.docsOnly(stats, events).answer("how do I allow a domain");
        assertTrue(reply.text().contains("Mark safe"), reply.text());
    }

    @Test
    void blockAQuestionAlsoFindsTheOverrideSection() {
        ChatBot.Reply reply = ChatBot.docsOnly(stats, events).answer("how do I block a domain");
        assertTrue(reply.text().contains("Mark safe"), reply.text());
    }

    @Test
    void everySuggestionChipFindsASection() {
        ChatBot bot = ChatBot.docsOnly(stats, events);
        for (String q : new String[]{"How does blocking work?", "What does servfail mean?",
                "How do I allow a domain?", "Is my data private?"}) {
            ChatBot.Reply reply = bot.answer(q);
            assertFalse(reply.text().startsWith("I can only answer"), q + " -> " + reply.text());
        }
    }

    @Test
    void privacyQuestionFindsThePrivacySection() {
        ChatBot.Reply reply = ChatBot.docsOnly(stats, events).answer("Is my data private?");
        assertTrue(reply.text().startsWith("Privacy"), reply.text());
    }

    @Test
    void offTopicQuestionListsTopicsInsteadOfGuessing() {
        ChatBot.Reply reply = ChatBot.docsOnly(stats, events).answer("best pizza recipe");
        assertTrue(reply.text().startsWith("I can only answer"), reply.text());
    }

    @Test
    void emptyQuestionGetsAPrompt() {
        ChatBot.Reply reply = ChatBot.docsOnly(stats, events).answer("   ");
        assertEquals("docs", reply.source());
        assertTrue(reply.text().startsWith("Ask me"));
    }

    @Test
    void modelAnswerIsReturnedAndPromptCarriesDocsAndLiveState() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            fake.inner = "Servfail means the upstream resolver failed.";
            ChatBot bot = new ChatBot(client(fake.url()), "m", stats, events);
            ChatBot.Reply reply = bot.answer("what does servfail mean");
            assertEquals("model", reply.source());
            assertEquals("Servfail means the upstream resolver failed.", reply.text());
            assertTrue(fake.lastBody.contains("Stat card meanings"));
            assertTrue(fake.lastBody.contains("stats total="));
            assertFalse(fake.lastBody.contains("\"format\""), "chat must not force JSON output");
            assertTrue(fake.lastBody.contains("num_predict"));
        }
    }

    @Test
    void modelErrorFallsBackToDocs() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            fake.status = 500;
            ChatBot.Reply reply = new ChatBot(client(fake.url()), "m", stats, events)
                    .answer("what does servfail mean");
            assertEquals("docs", reply.source());
            assertTrue(reply.text().contains("unavailable"));
            assertTrue(reply.text().contains("Stat card meanings"));
        }
    }

    @Test
    void blankModelAnswerFallsBackToDocs() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            fake.inner = "   ";
            ChatBot.Reply reply = new ChatBot(client(fake.url()), "m", stats, events)
                    .answer("what does servfail mean");
            assertEquals("docs", reply.source());
        }
    }

    @Test
    void aSecondQuestionWhileTheModelIsBusyGetsDocsInsteadOfQueueing() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            fake.delayMillis = 800;
            ChatBot bot = new ChatBot(client(fake.url()), "m", stats, events);
            Thread first = new Thread(() -> bot.answer("overrides"));
            first.start();
            Thread.sleep(200);
            ChatBot.Reply second = bot.answer("privacy");
            first.join();
            assertEquals("docs", second.source());
            assertTrue(second.text().contains("still answering"));
        }
    }

    @Test
    void recentlyBlockedHostsAreOnlySentToALoopbackModel() {
        events.add(new EventLog.Event(1, "BLOCK", "evil-casino.xyz", "list", null, null, "c"));
        ChatBot local = new ChatBot(client("http://127.0.0.1:11434"), "m", stats, events);
        ChatBot remote = new ChatBot(client("http://10.0.0.5:11434"), "m", stats, events);
        ChatBot cloud = new ChatBot(client("http://127.0.0.1:11434"), "gemma4:31b-cloud", stats, events);
        assertTrue(local.buildPrompt("q", local.rank("overrides")).contains("evil-casino.xyz"));
        assertFalse(remote.buildPrompt("q", remote.rank("overrides")).contains("evil-casino.xyz"));
        // A cloud tag is served by ollama.com even though the endpoint is loopback.
        assertFalse(cloud.buildPrompt("q", cloud.rank("overrides")).contains("evil-casino.xyz"));
    }

    @Test
    void cloudModelDetection() {
        assertTrue(ChatBot.isCloudModel("gemma4:31b-cloud"));
        assertTrue(ChatBot.isCloudModel("kimi-k2.7-code:cloud"));
        assertTrue(ChatBot.isCloudModel("qwen3:32b-CLOUD"));
        assertFalse(ChatBot.isCloudModel("gemma3:4b"));
        assertFalse(ChatBot.isCloudModel(null));
    }

    @Test
    void overlongQuestionsAreTruncated() throws Exception {
        try (FakeOllama fake = new FakeOllama()) {
            new ChatBot(client(fake.url()), "m", stats, events).answer("a".repeat(2000));
            assertTrue(fake.lastBody.contains("a".repeat(ChatBot.MAX_QUESTION_CHARS)));
            assertFalse(fake.lastBody.contains("a".repeat(ChatBot.MAX_QUESTION_CHARS + 1)));
        }
    }

    @Test
    void loopbackDetection() {
        assertTrue(ChatBot.isLoopback("http://127.0.0.1:11434"));
        assertTrue(ChatBot.isLoopback("http://localhost:11434"));
        assertFalse(ChatBot.isLoopback("http://192.168.1.9:11434"));
        assertFalse(ChatBot.isLoopback("not a url"));
    }
}
