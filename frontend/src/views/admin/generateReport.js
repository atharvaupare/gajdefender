import html2pdf from "html2pdf.js";
import { marked } from "marked"; // Make sure to install this using `npm install marked`

export const generateAndDownloadReport = async (scanResults, setReportText) => {
  const apiKey = process.env.REACT_APP_OPENAI_API_KEY;
  if (!apiKey) {
    alert("API key is not set. Please set it in the environment variables.");
    return;
  }

  try {
    // 1. Call OpenAI API to generate a markdown report
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          {
            role: "system",
            content:
              "You're a cybersecurity analyst writing detailed PDF reports.",
          },
          {
            role: "user",
            content: `Generate a malware analysis report for the following files:\n\n${JSON.stringify(
              scanResults,
              null,
              2
            )}\n\nGive it a proper title, summary, file-wise threat analysis, and conclusion. Format the report in markdown.`,
          },
        ],
      }),
    });

    const data = await response.json();
    const reportMarkdown =
      data.choices?.[0]?.message?.content || "No report generated.";

    // 2. Save markdown in state for live preview
    setReportText(reportMarkdown);

    // 3. Convert markdown to HTML
    const reportHTML = marked(reportMarkdown);

    // 4. Create printable DOM element
    const element = document.createElement("div");
    element.innerHTML = `
      <h1 style="text-align:center;">GajDefender Malware Analysis Report</h1>
      <div style="font-family: 'Segoe UI', sans-serif; font-size: 12px;">
        ${reportHTML}
      </div>
    `;

    // 5. Generate and download PDF
    await html2pdf()
      .set({
        margin: 10,
        filename: `GajDefender_Report_${
          new Date().toISOString().split("T")[0]
        }.pdf`,
        image: { type: "jpeg", quality: 0.98 },
        html2canvas: { scale: 2 },
        jsPDF: { unit: "mm", format: "a4", orientation: "portrait" },
      })
      .from(element)
      .save();
  } catch (error) {
    console.error("Error generating report:", error);
    alert("Failed to generate report.");
  }
};
