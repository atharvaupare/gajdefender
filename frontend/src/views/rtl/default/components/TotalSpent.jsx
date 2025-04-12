import React, { useRef, useState } from "react";
import { FiPlus } from "react-icons/fi";
import { motion } from "framer-motion";
import Card from "components/card";

const TotalSpent = () => {
  const fileInputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [scannedResult, setScannedResult] = useState(null);

  const handleClick = () => {
    fileInputRef.current.click();
  };

  const handleFileChange = (event) => {
    const uploadedFile = event.target.files[0];
    if (uploadedFile) {
      setFile(uploadedFile);
      setScannedResult(null); // Reset result on new file
    }
  };

  const handleScan = async () => {
    if (!file) return;
    setIsLoading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      // Step 1: Upload the file
      const uploadRes = await fetch("http://localhost:8000/files/upload", {
        method: "POST",
        body: formData,
      });

      const uploadData = await uploadRes.json();
      const uploadedPath = uploadData.file_path;

      if (!uploadedPath) throw new Error("Upload failed");

      // Step 2: Scan using uploaded file path
      const scanRes = await fetch("http://localhost:8000/hash/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ file_path: uploadedPath }),
      });

      const result = await scanRes.json();
      setScannedResult(result);
    } catch (error) {
      console.error("Error during scan:", error);
      setScannedResult({ error: "Scan failed. Try again." });
    }

    setIsLoading(false);
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

      {scannedResult && (
        <div className="mt-6 text-left text-sm text-navy-700 dark:text-white">
          <div className="font-semibold">Scan Result:</div>
          <pre className="mt-2 whitespace-pre-wrap rounded bg-gray-100 p-3 text-left dark:bg-gray-800">
            {JSON.stringify(scannedResult, null, 2)}
          </pre>
        </div>
      )}
    </Card>
  );
};

export default TotalSpent;
