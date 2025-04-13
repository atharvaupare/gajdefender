import React, { useRef, useState, useEffect } from "react";
import { motion } from "framer-motion";
import Card from "components/card";

const TotalSpent = () => {
  const fileInputRef = useRef(null);
  const resultsRef = useRef(null);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [processing, setProcessing] = useState(false);
  const [results, setResults] = useState([]);
  const [processedCount, setProcessedCount] = useState(0);
  const [concurrentLimit, setConcurrentLimit] = useState(5);

  useEffect(() => {
    if (results.length > 0 && resultsRef.current) {
      resultsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [results]);

  const handleFileChange = (e) => {
    const files = Array.from(e.target.files);
    if (files.length > 0) {
      setSelectedFiles(files);
      setResults([]);
      setProcessedCount(0);
    }
  };

  const calculateCombinedScore = (hashData, emberData) => {
    let vtScore = 0;
    const vtStats = hashData?.results?.virustotal?.analysis_stats;
    if (vtStats) {
      const total =
        vtStats.harmless +
        vtStats.undetected +
        vtStats.malicious +
        vtStats.suspicious;
      vtScore = (vtStats.malicious / (total || 1)) * 60;
    }

    const emberScore = emberData?.score ? parseFloat(emberData.score) * 100 : 0;
    const mbScore = hashData?.results?.malwarebazaar?.exists ? 100 : 0;

    const hasApiFindings = vtScore > 0 || mbScore > 0;

    if (hasApiFindings) {
      return Math.round(
        0.3 * ((vtScore + mbScore) / 2) +
          0.3 * emberScore +
          0.4 * (vtScore + mbScore)
      );
    }

    return Math.round(0.7 * emberScore + 0.3 * ((vtScore + mbScore) / 2));
  };

  const getScoreColor = (score) => {
    if (score <= 30) return "text-green-500";
    if (score <= 70) return "text-orange-400";
    return "text-red-500";
  };

  const getScoreBgColor = (score) => {
    if (score <= 30) return "bg-green-100";
    if (score <= 70) return "bg-orange-100";
    return "bg-red-100";
  };

  const saveResultsToLocalStorage = (results) => {
    try {
      const existingResults = JSON.parse(
        localStorage.getItem("securityScanResults") || "[]"
      );
      const resultsWithTimestamp = results.map((result) => ({
        ...result,
        timestamp: new Date().toISOString(),
        id: `scan-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      }));
      const updatedResults = [...resultsWithTimestamp, ...existingResults];
      localStorage.setItem(
        "securityScanResults",
        JSON.stringify(updatedResults.slice(0, 100))
      );
    } catch (error) {
      console.error("Error saving results:", error);
    }
  };

  const updateResultAtIndex = (index, newResultData) => {
    setResults((prev) => {
      const newResults = [...prev];
      newResults[index] = newResultData;
      return newResults;
    });
  };

  const processFile = async (file, index) => {
    try {
      updateResultAtIndex(index, {
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        status: "processing",
      });

      const uploadForm = new FormData();
      uploadForm.append("file", file);

      const uploadRes = await fetch("http://localhost:8000/files/upload", {
        method: "POST",
        body: uploadForm,
      });

      if (!uploadRes.ok) throw new Error(`Upload failed: ${uploadRes.status}`);

      const uploadData = await uploadRes.json();
      const filePath = uploadData.file_path;

      const hashRes = await fetch("http://localhost:8000/hash/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ file_path: filePath }),
      });

      if (!hashRes.ok) throw new Error(`Hash scan failed: ${hashRes.status}`);

      const emberForm = new FormData();
      emberForm.append("file", file);

      const emberRes = await fetch("http://localhost:8000/ember/", {
        method: "POST",
        body: emberForm,
      });

      if (!emberRes.ok)
        throw new Error(`Ember scan failed: ${emberRes.status}`);

      const [hashData, emberData] = await Promise.all([
        hashRes.json(),
        emberRes.json(),
      ]);

      const score = calculateCombinedScore(hashData, emberData);

      return {
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        sha256: hashData?.sha256,
        hashData,
        emberData,
        score,
        status: "completed",
        scanDate: new Date().toISOString(),
      };
    } catch (error) {
      console.error(`Error scanning ${file.name}:`, error);
      return {
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        error: true,
        errorMessage: error.message || "Processing failed",
        status: "error",
        scanDate: new Date().toISOString(),
      };
    }
  };

  const processFilesInBatches = async () => {
    const results = [];
    let currentIndex = 0;

    while (currentIndex < selectedFiles.length) {
      const batch = [];
      const batchSize = Math.min(
        concurrentLimit,
        selectedFiles.length - currentIndex
      );

      for (let i = 0; i < batchSize; i++) {
        const fileIndex = currentIndex + i;
        const file = selectedFiles[fileIndex];
        batch.push(
          processFile(file, fileIndex).then((result) => {
            setProcessedCount((prev) => prev + 1);
            return { result, index: fileIndex };
          })
        );
      }

      const batchResults = await Promise.all(batch);
      batchResults.forEach(({ result, index }) => {
        updateResultAtIndex(index, result);
        results[index] = result;
      });

      currentIndex += batchSize;
    }

    saveResultsToLocalStorage(
      results.filter(
        (result) =>
          result && (result.status === "completed" || result.status === "error")
      )
    );
    setProcessing(false);
  };

  const handleScan = async () => {
    if (selectedFiles.length === 0) return;

    setProcessing(true);
    setResults(
      selectedFiles.map((file) => ({
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        status: "queued",
      }))
    );
    setProcessedCount(0);

    await processFilesInBatches();
  };

  const formatFileSize = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  const resetUpload = () => {
    setSelectedFiles([]);
    setResults([]);
    setProcessedCount(0);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const files = Array.from(e.dataTransfer.files);
      setSelectedFiles(files);
      setResults([]);
      setProcessedCount(0);
    }
  };

  const handleConcurrentLimitChange = (e) => {
    const value = parseInt(e.target.value);
    if (!isNaN(value) && value > 0 && value <= 10) {
      setConcurrentLimit(value);
    }
  };

  return (
    <Card extra="!p-[20px]">
      <div className="mb-6 text-center text-xl font-bold text-navy-700 dark:text-white">
        Advanced File Security Analyzer
      </div>

      <div className="mb-4">
        <div
          className="cursor-pointer rounded-lg border-2 border-dashed border-blue-400 bg-gray-50 p-6 text-center transition-all duration-200 hover:bg-blue-50"
          onClick={() => fileInputRef.current.click()}
          onDragOver={handleDragOver}
          onDrop={handleDrop}
        >
          <div className="flex flex-col items-center justify-center gap-2">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-10 w-10 text-blue-500"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path
                fillRule="evenodd"
                d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zM6.293 6.707a1 1 0 010-1.414l3-3a1 1 0 011.414 0l3 3a1 1 0 01-1.414 1.414L11 5.414V13a1 1 0 11-2 0V5.414L7.707 6.707a1 1 0 01-1.414 0z"
                clipRule="evenodd"
              />
            </svg>
            <p className="font-medium text-gray-700">
              Drag files here or click to upload
            </p>
            <p className="text-sm text-gray-500">Support for multiple files</p>
          </div>
          <input
            id="file-upload"
            type="file"
            multiple
            className="hidden"
            ref={fileInputRef}
            onChange={handleFileChange}
          />
        </div>
      </div>

      {selectedFiles.length > 0 && (
        <div className="mb-4 rounded-lg bg-gray-100 p-3 dark:bg-gray-800">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium text-navy-700 dark:text-white">
              {selectedFiles.length} file(s) selected
            </span>
            {!processing && (
              <button
                onClick={resetUpload}
                className="text-xs text-red-500 transition-all hover:text-red-700"
              >
                Clear all
              </button>
            )}
          </div>
          <div className="max-h-32 overflow-y-auto">
            {selectedFiles.map((file, idx) => (
              <div
                key={idx}
                className="mb-1 flex items-center text-xs text-gray-600 dark:text-gray-400"
              >
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="mr-1 h-3 w-3 text-blue-500"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <path
                    fillRule="evenodd"
                    d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z"
                    clipRule="evenodd"
                  />
                </svg>
                <span className="max-w-sm truncate">{file.name}</span>
                <span className="ml-2">({formatFileSize(file.size)})</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mb-6 flex flex-wrap items-center justify-center gap-4">
        <div className="flex items-center">
          <label
            htmlFor="concurrent-limit"
            className="mr-2 text-sm font-medium text-navy-700 dark:text-white"
          >
            Concurrent files:
          </label>
          <input
            id="concurrent-limit"
            type="number"
            min="1"
            max="10"
            value={concurrentLimit}
            onChange={handleConcurrentLimitChange}
            className="w-16 rounded-md border border-gray-300 px-2 py-1 text-sm"
            disabled={processing}
          />
        </div>

        <button
          disabled={selectedFiles.length === 0 || processing}
          onClick={handleScan}
          className={`rounded-lg px-6 py-2 font-semibold text-white transition ${
            selectedFiles.length === 0 || processing
              ? "cursor-not-allowed bg-gray-400"
              : "bg-blue-500 hover:bg-blue-600"
          }`}
        >
          {processing
            ? `Scanning (${processedCount}/${selectedFiles.length})`
            : "Scan All Files"}
        </button>
      </div>

      {processing && (
        <div className="mb-6">
          <div className="h-2.5 w-full rounded-full bg-gray-200 dark:bg-gray-700">
            <div
              className="h-2.5 rounded-full bg-blue-500 transition-all duration-300"
              style={{
                width: `${(processedCount / selectedFiles.length) * 100}%`,
              }}
            ></div>
          </div>
          <p className="mt-1 text-center text-xs text-gray-500">
            Processed {processedCount} of {selectedFiles.length}
          </p>
        </div>
      )}

      {results.length > 0 && (
        <div className="mt-6" ref={resultsRef}>
          <h3 className="text-md mb-3 font-semibold text-navy-700 dark:text-white">
            Scan Results
          </h3>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {results.map((result, index) => (
              <motion.div
                key={index}
                className="rounded-lg border border-gray-200 bg-white p-4 shadow-md dark:border-gray-700 dark:bg-gray-800"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4, delay: index * 0.05 }}
              >
                <div className="mb-2 flex items-start justify-between">
                  <div>
                    <h4 className="text-md max-w-xs truncate font-semibold text-navy-700 dark:text-white">
                      {result.fileName}
                    </h4>
                    <p className="text-xs text-gray-500">{result.fileSize}</p>
                  </div>

                  {result.status === "queued" ? (
                    <span className="text-xs text-gray-500">Queued</span>
                  ) : result.status === "processing" ? (
                    <div className="flex items-center">
                      <div className="border-t-transparent mr-2 h-4 w-4 animate-spin rounded-full border-2 border-blue-500"></div>
                      <span className="text-xs text-blue-500">
                        Processing...
                      </span>
                    </div>
                  ) : result.status === "error" ? (
                    <div className="flex items-center rounded bg-red-100 px-2 py-1 text-xs text-red-600">
                      <svg
                        xmlns="http://www.w3.org/2000/svg"
                        className="mr-1 h-3 w-3"
                        viewBox="0 0 20 20"
                        fill="currentColor"
                      >
                        <path
                          fillRule="evenodd"
                          d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                          clipRule="evenodd"
                        />
                      </svg>
                      Failed
                    </div>
                  ) : (
                    <div
                      className={`flex items-center rounded-full px-3 py-1 text-sm font-medium ${getScoreBgColor(
                        result.score
                      )} ${getScoreColor(result.score)}`}
                    >
                      {result.score}/100
                    </div>
                  )}
                </div>

                {result.status === "error" && (
                  <div className="mt-2 rounded bg-red-50 p-2 text-xs text-red-500">
                    {result.errorMessage}
                  </div>
                )}

                {result.status === "completed" && (
                  <div className="mt-2">
                    <div className="mb-1 text-xs text-gray-700 dark:text-gray-300">
                      <span className="font-semibold">SHA256:</span>
                      <span className="ml-1 break-all font-mono text-xs">
                        {result.sha256}
                      </span>
                    </div>

                    <div className="mt-3 grid grid-cols-2 gap-2">
                      <div className="rounded bg-gray-50 p-2 dark:bg-gray-700">
                        <p className="mb-1 text-xs font-semibold text-navy-700 dark:text-white">
                          VirusTotal
                        </p>
                        <p className="text-xs text-gray-700 dark:text-gray-300">
                          <span className="font-semibold">Threat:</span>{" "}
                          {result.hashData?.results?.virustotal?.threat_name ||
                            "None"}
                        </p>
                        <p className="text-xs text-gray-700 dark:text-gray-300">
                          <span className="font-semibold">Score:</span>{" "}
                          {result.hashData?.results?.virustotal
                            ? `${Math.round(
                                (result.hashData.results.virustotal
                                  .analysis_stats.malicious /
                                  (result.hashData.results.virustotal
                                    .analysis_stats.harmless +
                                    result.hashData.results.virustotal
                                      .analysis_stats.undetected +
                                    result.hashData.results.virustotal
                                      .analysis_stats.malicious +
                                    result.hashData.results.virustotal
                                      .analysis_stats.suspicious)) *
                                  100
                              )}%`
                            : "N/A"}
                        </p>
                      </div>

                      <div className="rounded bg-gray-50 p-2 dark:bg-gray-700">
                        <p className="mb-1 text-xs font-semibold text-navy-700 dark:text-white">
                          MalwareBazaar
                        </p>
                        <p className="text-xs text-gray-700 dark:text-gray-300">
                          <span className="font-semibold">Status:</span>{" "}
                          {result.hashData?.results?.malwarebazaar?.exists
                            ? "Known Malware"
                            : "Not Found"}
                        </p>
                        <p className="text-xs text-gray-700 dark:text-gray-300">
                          <span className="font-semibold">First Seen:</span>{" "}
                          {result.hashData?.results?.malwarebazaar
                            ?.first_seen || "N/A"}
                        </p>
                      </div>

                      <div className="col-span-2 rounded bg-gray-50 p-2 dark:bg-gray-700">
                        <p className="mb-1 text-xs font-semibold text-navy-700 dark:text-white">
                          EMBER Analysis
                        </p>
                        <p className="text-xs text-gray-700 dark:text-gray-300">
                          <span className="font-semibold">Prediction:</span>{" "}
                          {result.emberData?.label || "N/A"}
                        </p>
                        <p className="text-xs text-gray-700 dark:text-gray-300">
                          <span className="font-semibold">Confidence:</span>{" "}
                          {result.emberData?.score
                            ? `${(
                                parseFloat(result.emberData.score) * 100
                              ).toFixed(1)}%`
                            : "N/A"}
                        </p>
                      </div>
                    </div>
                  </div>
                )}
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </Card>
  );
};

export default TotalSpent;
