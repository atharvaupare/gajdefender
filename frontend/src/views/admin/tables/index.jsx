import React, { useState, useEffect } from "react";
import CheckTable from "./components/CheckTable";
import {
  columnsDataDevelopment,
  columnsDataCheck,
  columnsDataColumns,
  columnsDataComplex,
} from "./variables/columnsData";
import tableDataDevelopment from "./variables/tableDataDevelopment.json";
import tableDataCheck from "./variables/tableDataCheck.json";
import tableDataColumns from "./variables/tableDataColumns.json";
import tableDataComplex from "./variables/tableDataComplex.json";
import DevelopmentTable from "./components/DevelopmentTable";
import ColumnsTable from "./components/ColumnsTable";
import ComplexTable from "./components/ComplexTable";
import Card from "components/card";

const Tables = () => {
  const [scanResults, setScanResults] = useState([]);
  const [filteredResults, setFilteredResults] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [dateFilter, setDateFilter] = useState("all");
  const [scoreFilter, setScoreFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("all");
  const [stats, setStats] = useState({
    total: 0,
    clean: 0,
    suspicious: 0,
    malicious: 0,
    failed: 0,
  });

  useEffect(() => {
    // Load scan results from localStorage
    const loadResults = () => {
      try {
        setLoading(true);
        const savedResults = localStorage.getItem("securityScanResults");
        if (savedResults) {
          const parsedResults = JSON.parse(savedResults);
          setScanResults(parsedResults);
          setFilteredResults(parsedResults);

          // Calculate statistics
          const newStats = {
            total: parsedResults.length,
            clean: parsedResults.filter((r) => r.score <= 30).length,
            suspicious: parsedResults.filter(
              (r) => r.score > 30 && r.score <= 70
            ).length,
            malicious: parsedResults.filter((r) => r.score > 70).length,
            failed: parsedResults.filter((r) => r.status === "error").length,
          };

          setStats(newStats);
        }
        setLoading(false);
      } catch (error) {
        console.error("Error loading scan results:", error);
        setLoading(false);
      }
    };

    loadResults();

    // Set up event listener for storage changes
    const handleStorageChange = () => {
      loadResults();
    };

    window.addEventListener("storage", handleStorageChange);

    // Check for new results every 10 seconds
    const intervalId = setInterval(loadResults, 10000);

    return () => {
      window.removeEventListener("storage", handleStorageChange);
      clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    // Apply filters
    let results = [...scanResults];

    // Filter by tab/status
    if (activeTab !== "all") {
      switch (activeTab) {
        case "clean":
          results = results.filter((r) => r.score <= 30);
          break;
        case "suspicious":
          results = results.filter((r) => r.score > 30 && r.score <= 70);
          break;
        case "malicious":
          results = results.filter((r) => r.score > 70);
          break;
        case "failed":
          results = results.filter((r) => r.status === "error");
          break;
      }
    }

    // Filter by search term
    if (searchTerm) {
      results = results.filter(
        (r) =>
          r.fileName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
          r.sha256?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Filter by date
    if (dateFilter !== "all") {
      const now = new Date();
      let compareDate = new Date();

      switch (dateFilter) {
        case "today":
          compareDate.setHours(0, 0, 0, 0);
          break;
        case "week":
          compareDate.setDate(now.getDate() - 7);
          break;
        case "month":
          compareDate.setMonth(now.getMonth() - 1);
          break;
      }

      results = results.filter((r) => {
        const scanDate = new Date(r.timestamp || r.scanDate);
        return scanDate >= compareDate;
      });
    }

    // Filter by score
    if (scoreFilter !== "all") {
      switch (scoreFilter) {
        case "clean":
          results = results.filter((r) => r.score <= 30);
          break;
        case "suspicious":
          results = results.filter((r) => r.score > 30 && r.score <= 70);
          break;
        case "malicious":
          results = results.filter((r) => r.score > 70);
          break;
      }
    }

    setFilteredResults(results);
  }, [scanResults, searchTerm, dateFilter, scoreFilter, activeTab]);

  const clearAllResults = () => {
    if (window.confirm("Are you sure you want to clear all scan history?")) {
      localStorage.removeItem("securityScanResults");
      setScanResults([]);
      setFilteredResults([]);
      setStats({
        total: 0,
        clean: 0,
        suspicious: 0,
        malicious: 0,
        failed: 0,
      });
    }
  };

  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getScoreClass = (score) => {
    if (score <= 30) return "text-green-500";
    if (score <= 70) return "text-orange-500";
    return "text-red-500";
  };

  const getScoreBadgeClass = (score) => {
    if (score <= 30) return "bg-green-100 text-green-800";
    if (score <= 70) return "bg-orange-100 text-orange-800";
    return "bg-red-100 text-red-800";
  };

  const tabClasses = (tab) =>
    `px-4 py-2 font-medium text-sm rounded-md transition-all ${
      activeTab === tab
        ? "bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300"
        : "text-gray-600 hover:text-gray-800 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-800"
    }`;

  return (
    <div>
      <div className="mt-5">
        <Card extra="!p-[20px]">
          <div className="mb-2 flex flex-col items-start justify-between lg:flex-row lg:items-center">
            <div>
              {/* <h2 className="text-xl font-bold text-navy-700 dark:text-white">
                Security Scan History
              </h2> */}
              <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">
                View and filter your previous file scans
              </p>
            </div>

            <div className="mt-4 flex items-center gap-2 lg:mt-0">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search files..."
                  className="rounded-md border px-3 py-2 pr-8 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 dark:border-navy-700 dark:bg-navy-800"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
                <svg
                  className="absolute right-2 top-2.5 text-gray-400"
                  width="16"
                  height="16"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                  />
                </svg>
              </div>

              <select
                className="rounded-md border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 dark:border-navy-700 dark:bg-navy-800"
                value={dateFilter}
                onChange={(e) => setDateFilter(e.target.value)}
              >
                <option value="all">All time</option>
                <option value="today">Today</option>
                <option value="week">Last 7 days</option>
                <option value="month">Last 30 days</option>
              </select>

              <select
                className="rounded-md border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400 dark:border-navy-700 dark:bg-navy-800"
                value={scoreFilter}
                onChange={(e) => setScoreFilter(e.target.value)}
              >
                <option value="all">All scores</option>
                <option value="clean">Clean (0-30)</option>
                <option value="suspicious">Suspicious (31-70)</option>
                <option value="malicious">Malicious (71-100)</option>
              </select>

              <button
                onClick={clearAllResults}
                className="rounded-md px-3 py-2 text-sm text-red-600 transition hover:bg-red-50 hover:text-red-800 dark:hover:bg-red-900"
              >
                Clear All
              </button>
            </div>
          </div>

          <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-5">
            <div className="rounded-lg border border-gray-100 bg-white p-3 shadow dark:border-navy-700 dark:bg-navy-800">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Total Scans
              </p>
              <p className="text-2xl font-semibold text-navy-700 dark:text-white">
                {stats.total}
              </p>
            </div>

            <div className="rounded-lg border border-gray-100 bg-white p-3 shadow dark:border-navy-700 dark:bg-navy-800">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Clean Files
              </p>
              <p className="text-2xl font-semibold text-green-500">
                {stats.clean}
              </p>
            </div>

            <div className="rounded-lg border border-gray-100 bg-white p-3 shadow dark:border-navy-700 dark:bg-navy-800">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Suspicious
              </p>
              <p className="text-2xl font-semibold text-orange-500">
                {stats.suspicious}
              </p>
            </div>

            <div className="rounded-lg border border-gray-100 bg-white p-3 shadow dark:border-navy-700 dark:bg-navy-800">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Malicious
              </p>
              <p className="text-2xl font-semibold text-red-500">
                {stats.malicious}
              </p>
            </div>

            <div className="rounded-lg border border-gray-100 bg-white p-3 shadow dark:border-navy-700 dark:bg-navy-800">
              <p className="text-sm text-gray-500 dark:text-gray-400">
                Failed Scans
              </p>
              <p className="text-2xl font-semibold text-gray-500">
                {stats.failed}
              </p>
            </div>
          </div>

          {/* Category tabs */}
          <div className="mb-6 flex flex-wrap gap-2">
            <button
              className={tabClasses("all")}
              onClick={() => setActiveTab("all")}
            >
              All
            </button>

            <button
              className={tabClasses("clean")}
              onClick={() => setActiveTab("clean")}
            >
              Clean
            </button>

            <button
              className={tabClasses("suspicious")}
              onClick={() => setActiveTab("suspicious")}
            >
              Suspicious
            </button>

            <button
              className={tabClasses("malicious")}
              onClick={() => setActiveTab("malicious")}
            >
              Malicious
            </button>

            <button
              className={tabClasses("failed")}
              onClick={() => setActiveTab("failed")}
            >
              Failed
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-10">
              <div className="h-10 w-10 animate-spin rounded-full border-b-2 border-blue-500"></div>
            </div>
          ) : filteredResults.length === 0 ? (
            <div className="rounded-lg bg-gray-50 py-12 text-center dark:bg-navy-900">
              <svg
                className="mx-auto h-12 w-12 text-gray-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
              <h3 className="mt-2 text-lg font-medium text-gray-900 dark:text-white">
                No results found
              </h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
                {scanResults.length > 0
                  ? "Try adjusting your filters or search term."
                  : "Scan some files to see results here."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg shadow">
              <table className="w-full text-left text-sm text-gray-700 dark:text-gray-300">
                <thead className="bg-gray-50 text-xs uppercase text-gray-700 dark:bg-navy-800 dark:text-gray-400">
                  <tr>
                    <th className="px-6 py-3">File Name</th>
                    <th className="px-6 py-3">Size</th>
                    <th className="px-6 py-3">SHA256</th>
                    <th className="px-6 py-3">Scan Date</th>
                    <th className="px-6 py-3">Score</th>
                    <th className="px-6 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredResults.map((result, index) => (
                    <tr
                      key={result.id || index}
                      className="border-b bg-white hover:bg-gray-50 dark:border-navy-700 dark:bg-navy-900 dark:hover:bg-navy-800"
                    >
                      <td className="max-w-xs truncate px-6 py-4 font-medium">
                        {result.fileName}
                      </td>
                      <td className="px-6 py-4">{result.fileSize}</td>
                      <td className="max-w-xs truncate px-6 py-4 font-mono text-xs">
                        {result.sha256 || "N/A"}
                      </td>
                      <td className="px-6 py-4">
                        {formatDate(result.timestamp || result.scanDate)}
                      </td>
                      <td className="px-6 py-4">
                        {result.status === "error" ? (
                          <span className="rounded-full bg-red-100 px-2 py-1 text-xs font-medium text-red-800">
                            Failed
                          </span>
                        ) : (
                          <span
                            className={`rounded-full px-2 py-1 text-xs font-medium ${getScoreBadgeClass(
                              result.score
                            )}`}
                          >
                            {result.score}/100
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4">
                        <button
                          className="mr-2 text-blue-600 hover:text-blue-900 dark:hover:text-blue-400"
                          onClick={() => {
                            // View details - you would implement this functionality
                            console.log("View details for", result);
                            // You could show a modal or navigate to a detail page
                          }}
                        >
                          View
                        </button>
                        <button
                          className="text-red-600 hover:text-red-900 dark:hover:text-red-400"
                          onClick={() => {
                            // Delete single result
                            if (window.confirm("Delete this scan result?")) {
                              const updatedResults = scanResults.filter(
                                (r) =>
                                  (r.id || r.sha256) !==
                                  (result.id || result.sha256)
                              );
                              localStorage.setItem(
                                "securityScanResults",
                                JSON.stringify(updatedResults)
                              );
                              setScanResults(updatedResults);
                            }
                          }}
                        >
                          Delete
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
};

export default Tables;
