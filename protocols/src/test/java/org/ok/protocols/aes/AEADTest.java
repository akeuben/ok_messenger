package org.ok.protocols.aes;

import org.junit.jupiter.api.Test;
import org.ok.protocols.Block;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class AEADTest {
    @Test
    public void TestAEAD() {
        String[] messages = new String[] {
                "Hello, World!",
                "This is a long multiblock string as it is longer than a single block in AES-256. This should successfully decrypt to the same value as you are reading right now!",
                "Where are we?",
                "What the hell is going on?",
                "The dust has only just begun to form",
                "Sinking, feeling",
                "This can't be happening",
                "When busy streets",
                "Hide and seek",
                "They were here first",
                "Mm, what'd you say?",
                "Mm, that you only meant well",
                "Well of course you did",
                "Mm, that it's all for the best",
                "Mm, that it's just what we need",
                "Ransom notes keep falling out your mouth",
                "Mid-sweet talk, newspaper word cutouts",
                "Speak no feeling, no, I don't believe you",
                "You don't care a bit, you don't care a bit",
                "Yahaha! You found me!",
                "Its dangerous to go alone! Take this.",
                "You've met with a terrible fate, haven't you?",
                "It’s a little story I like to call The Legend of Groose!",
                "\"I call it the Groosenator\" -Groose",
                "Hey! Listen!",
                "Tingle, Tingle! Kooloo-Limpah!",
                "Dah-na-na-na-naaaaaaaa!",
                "The blood moon rises once again...",
                "Master, the batteries in your Wii Remote are nearly depleted",
                "Despite everything, it's still you",
                "You should be smiling, too. Aren't you excited? Aren't you happy? You're going to be free.",
                "It fill you with determination",
                "If you'll be my bodyguard",
                "I can be your long lost pal",
                "And Betty, when you call me, you can call me Al",
                "Frogs are people too",
                "So be it. Let your will be done.",
                "What meaning can we find in a world that has no purpose?",
                "In the beginning were the words...",
                "You were always meant to defy me. That was the final trial.",
                "Two plus two is- f- f- f-... ten. In base 4! I'm Fine!",
                "How are you? Because I'm a potato.",
                "well... this is the part where he kills us",
                "Hello, this is the part where i kill you",
                "When life gives you lemons, don't make lemonade!",
                "I don't want your damn lemons; what am I supposed to do with these?",
                "Make life rue the day it thought it could give Cave Johnson lemons!",
                "I'm gonna get my engineers to invent a combustible lemon that burns your house down!",
                "We do what we must because we can.",
                "I punched those numbers into my calculator it makes a happy face.",
                "Are you still there?",
                "Target lost.",
                "Make it so, Number One.",
                "Engage.",
                "Tea. Earl Grey. Hot.",
                "Science compels us to explode the sun!",
                "The past is past, now, but that’s… you know, that’s okay! It’s never really gone completely. The future is always built on the past, even if we won’t get to see it.",
                "It’s the kind of thing that makes you glad you stopped and smelled the pine trees along the way, you know?",
                "We do not have much connection, you and I. Still, this encounter feels special. I hope you won't mind if I think of you as a friend.",
                "We only get so much time, don't we? Ah, there was still more I wanted to do... How unlucky to have been born at the end of the universe.",
                "The universe is, and we are.",
                "I believe we've reached the end of our journey. All that remains is to collapse the innumerable possibilities before us. Are you ready to learn what comes next?",
                "The past is past, now, but that's... you know, that's okay! It's never really gone completely. The future is always built on the past, even if we won't get to see it.",
                "Come, sit with me, my fellow traveler. Let's sit and watch the stars die.",
                "Are you certain you want to remember me?",
                "It's tempting to linger in this moment, while every possibility still exists. But unless they are collapsed by an observer, they will never be more than possibilities.",
                "I believe we’ve reached the end of our journey. All that remains is to collapse the innumerable possibilities before us. Are you ready to learn what comes next?",
                "Every decision is made in darkness. Only by making a choice can we learn whether it was right or not.",
        };
        for(String message : messages) {
            Block msg = new Block(message);

            Block AD = Block.fromHexString("44116f1a6af9c79c44116f1a6af9c79c");

            AESKey key = AESKey.fromHexString("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");

            Block encrypted = AEAD.encrypt(msg, key, AD);
            Block decrypted = AEAD.decrypt(encrypted, key, AD);

            assertEquals(msg, decrypted);
        }
    }
}
