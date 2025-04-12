import React, { useRef, useState } from "react";
import { FiPlus } from "react-icons/fi";
import { motion } from "framer-motion";
import { MdCheckCircle, MdCancel } from "react-icons/md";
import Card from "components/card";

const TotalSpent = () => {
  const fileInputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [hashScanResult, setHashScanResult] = useState(null);
  const [emberScanResult, setEmberScanResult] = useState(null);
  const [combinedScore, setCombinedScore] = useState(null);

  const handleClick = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile) {
      setFile(uploadedFile);
      setHashScanResult(null);
      setEmberScanResult(null);
      setCombinedScore(null);
    }
  };

  const calculateCombinedScore = (hash, ember) => {
    let hashScore = 0;
    const stats = hash?.results?.virustotal?.analysis_stats;
    if (stats) {
      const total =
        stats.harmless + stats.undetected + stats.malicious + stats.suspicious;
      const maliciousRatio = stats.malicious / (total || 1);
      hashScore = maliciousRatio * 60;
    }

    const emberScore = ember?.score ? parseFloat(ember.score) * 40 : 0;
    return Math.round(hashScore + emberScore);
  };

  const handleScan = async () => {
    if (!file) return;
    setIsLoading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const uploadRes = await fetch("http://localhost:8000/files/upload", {
        method: "POST",
        body: formData,
      });
      const uploadData = await uploadRes.json();
      const uploadedPath = uploadData.file_path;
      if (!uploadedPath) throw new Error("Upload failed");

      const hashScanRes = await fetch("http://localhost:8000/hash/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: uploadedPath }),
      });
      const hashData = await hashScanRes.json();
      setHashScanResult(hashData);

      const emberRes = await fetch("http://localhost:8000/ember/", {
        method: "POST",
        body: formData,
      });
      const emberData = await emberRes.json();
      setEmberScanResult(emberData);

      const score = calculateCombinedScore(hashData, emberData);
      setCombinedScore(score);
    } catch (error) {
      console.error("Scan failed:", error);
    }

    setIsLoading(false);
  };

  const getScoreColor = (score) => {
    if (score <= 30) return "text-green-500";
    if (score <= 70) return "text-orange-400";
    return "text-red-500";
  };

  return (
    <Card extra="!p-[20px] text-center">
      <div className="mb-6 text-xl font-bold text-navy-700 dark:text-white">
        Upload Single File
      </div>

      <div className="mb-4 flex justify-center">
        <div
          className="flex h-40 w-40 cursor-pointer items-center justify-center rounded-xl border-2 border-dashed border-blue-500 transition hover:bg-blue-50"
          onClick={handleClick}
        >
          <FiPlus className="text-4xl text-blue-500" />
          <input
            type="file"
            accept=".exe,.dll,.bin,.dat"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
          />
        </div>
      </div>

      {file && (
        <div className="mb-4 text-sm text-navy-700 dark:text-white">
          Selected: <strong>{file.name}</strong>
        </div>
      )}

      <button
        disabled={!file || isLoading}
        onClick={handleScan}
        className={`rounded-lg px-6 py-2 text-white transition ${
          file && !isLoading
            ? "bg-blue-500 hover:bg-blue-600"
            : "cursor-not-allowed bg-gray-300"
        }`}
      >
        {isLoading ? "Scanning..." : "Scan"}
      </button>

      {isLoading && (
        <motion.div
          className="mt-4 flex justify-center"
          animate={{ rotate: 360 }}
          transition={{ repeat: Infinity, duration: 1, ease: "linear" }}
        >
          <div className="border-t-transparent h-6 w-6 animate-spin rounded-full border-4 border-blue-500" />
        </motion.div>
      )}

      {combinedScore !== null && (
        <motion.div
          className="mt-6 rounded-md bg-gray-50 p-4 text-center shadow-inner dark:bg-gray-800"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <div className={`text-4xl font-bold ${getScoreColor(combinedScore)}`}>
            {combinedScore}/100
          </div>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">
            Combined Threat Score (Hash + EMBER)
          </p>
        </motion.div>
      )}

      {(hashScanResult || emberScanResult) && (
        <motion.div
          className="mt-6 rounded-lg bg-white p-4 text-left shadow-md dark:bg-gray-900"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
        >
          <h4 className="text-md mb-2 font-bold text-navy-700 dark:text-white">
            Details
          </h4>
          {hashScanResult && (
            <>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>SHA256:</strong> {hashScanResult.sha256}
              </p>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>Type:</strong>{" "}
                {hashScanResult.results?.virustotal?.type_description ??
                  "Unknown"}
              </p>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>Threat Name:</strong>{" "}
                {hashScanResult.results?.virustotal?.threat_name ?? "N/A"}
              </p>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>VT Detected:</strong>{" "}
                {hashScanResult.results?.virustotal?.analysis_stats
                  ?.malicious ?? 0}{" "}
                malicious /{" "}
                {Object.values(
                  hashScanResult.results?.virustotal?.analysis_stats || {}
                ).reduce((a, b) => a + b, 0)}{" "}
                total engines
              </p>
            </>
          )}

          {emberScanResult && (
            <>
              <div className="my-2 border-t border-gray-300 dark:border-gray-700" />
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>EMBER Label:</strong> {emberScanResult.label ?? "N/A"}
              </p>
              <p className="text-sm text-gray-700 dark:text-gray-300">
                <strong>EMBER Score:</strong> {emberScanResult.score ?? "N/A"}
              </p>
              {emberScanResult.family && (
                <p className="text-sm text-gray-700 dark:text-gray-300">
                  <strong>Malware Family:</strong> {emberScanResult.family}
                </p>
              )}
            </>
          )}
        </motion.div>
      )}
    </Card>
  );
};

export default TotalSpent;
