import OpenAI from "openai";

const openai = new OpenAI();

export async function ask(prompt: string) {
  return openai.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: prompt }],
  });
}
