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
      const response = await fetch("http://localhost:8000/ember/", {
        method: "POST",
        body: formData,
      });

      const result = await response.json();
      setScannedResult(result);
    } catch (error) {
      console.error("Error scanning file:", error);
      setScannedResult({ error: "Scan failed. Try again." });
    }

    setIsLoading(false);
  };

  return (
    <Card extra="!p-[20px] text-center">
      <div className="text-xl font-bold text-navy-700 dark:text-white mb-6">
        Upload Single File
      </div>

      <div className="flex justify-center mb-4">
        <div
          className="w-40 h-40 flex items-center justify-center border-2 border-dashed border-blue-500 rounded-xl cursor-pointer hover:bg-blue-50 transition"
          onClick={handleClick}
        >
          <FiPlus className="text-blue-500 text-4xl" />
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
        className={`px-6 py-2 rounded-lg text-white transition ${
          file && !isLoading
            ? "bg-blue-500 hover:bg-blue-600"
            : "bg-gray-300 cursor-not-allowed"
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
          <div className="w-6 h-6 border-4 border-blue-500 border-t-transparent rounded-full animate-spin" />
        </motion.div>
      )}

      {scannedResult && (
        <div className="mt-6 text-left text-sm text-navy-700 dark:text-white">
          <div className="font-semibold">Scan Result:</div>
          <pre className="bg-gray-100 dark:bg-gray-800 p-3 mt-2 rounded text-left whitespace-pre-wrap">
            {JSON.stringify(scannedResult, null, 2)}
          </pre>
        </div>
      )}
    </Card>
  );
};

export default TotalSpent;
