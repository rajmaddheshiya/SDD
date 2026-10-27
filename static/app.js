
(() => {
    const $ = (selector) => document.querySelector(selector);

    const state = {
        tab: "upload",
        file: null,
        report: null,
        severity: "all",
        type: "all"
    };

    const MAX_ROWS = 500;

    const SAMPLE = `Customer record (FAKE TEST DATA)
Email: rahul.sharma@example.com
Phone: 9876543210
PAN: ABCDE1234F
Credit card: 4111 1111 1111 1111
CVV: 123
DOB: 14/03/1992
Server IP: 192.168.10.25
password = MyS3cretPass!
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
Order total 4500 rupees, invoice 1234567`;

    // Switch between file upload and text input.
    document.querySelectorAll(".tab").forEach((tab) => {
        tab.addEventListener("click", () => {
            state.tab = tab.dataset.tab;

            document.querySelectorAll(".tab").forEach((item) => {
                const active = item === tab;
                item.classList.toggle("active", active);
                item.setAttribute("aria-selected", String(active));
            });

            $("#tab-upload").hidden = state.tab !== "upload";
            $("#tab-paste").hidden = state.tab !== "paste";
        });
    });

    // Handle file selection and drag-and-drop.
    const dropArea = $("#drop");
    const fileInput = $("#file");

    function setFile(file) {
        state.file = file;
        $("#drop-title").textContent = file
            ? file.name
            : "Drop a file here or click to choose";
    }

    fileInput.addEventListener("change", () => {
        setFile(fileInput.files[0] || null);
    });

    dropArea.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            fileInput.click();
        }
    });

    ["dragenter", "dragover"].forEach((eventName) => {
        dropArea.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropArea.classList.add("over");
        });
    });

    ["dragleave", "drop"].forEach((eventName) => {
        dropArea.addEventListener(eventName, (event) => {
            event.preventDefault();
            dropArea.classList.remove("over");
        });
    });

    dropArea.addEventListener("drop", (event) => {
        const file = event.dataTransfer.files[0];

        if (file) {
            setFile(file);
        }
    });

    // Load sample data into the text area.
    $("#sample").addEventListener("click", () => {
        $('[data-tab="paste"]').click();
        $("#paste").value = SAMPLE;
    });

    function showStatus(message, isError = false) {
        const status = $("#status");
        status.textContent = message;
        status.classList.toggle("err", isError);
    }

    // Upload the selected file and request a scan.
    $("#scan").addEventListener("click", async () => {
        let file;

        if (state.tab === "upload") {
            file = state.file;
        } else {
            const text = $("#paste").value;

            if (text.trim()) {
                file = new File([text], "pasted-text.txt", {
                    type: "text/plain"
                });
            }
        }

        if (!file) {
            showStatus("Choose a file or paste some text first.", true);
            return;
        }

        const formData = new FormData();
        formData.append("file", file);

        const scanButton = $("#scan");
        scanButton.disabled = true;
        showStatus("Scanning...");

        try {
            const response = await fetch("/scan", {
                method: "POST",
                body: formData
            });

            const report = await response.json();

            if (!response.ok) {
                throw new Error(report.error || "Scan failed.");
            }

            state.report = report;
            state.severity = "all";
            state.type = "all";

            renderReport();
            showStatus("Scan complete.");

            $("#results").scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        } catch (error) {
            showStatus(error.message || "Something went wrong.", true);
        } finally {
            scanButton.disabled = false;
        }
    });

    // Create elements safely without inserting file content as HTML.
    function createElement(tag, className = "", text = "") {
        const element = document.createElement(tag);

        if (className) {
            element.className = className;
        }

        element.textContent = text;
        return element;
    }

    // Display the summary and available filters.
    function renderReport() {
        const report = state.report;

        $("#results").hidden = false;
        $("#res-sub").textContent =
            `${report.filename} · ${report.units} text blocks checked`;

        $("#n-risk").textContent = report.risk;
        $("#stat-risk").className = `stat risk r-${report.risk}`;

        $("#n-total").textContent = report.total;
        $("#n-high").textContent = report.by_severity.high;
        $("#n-medium").textContent = report.by_severity.medium;
        $("#n-low").textContent = report.by_severity.low;

        const warnings = $("#warnings");
        warnings.replaceChildren();

        (report.warnings || []).forEach((message) => {
            warnings.append(createElement("div", "warn", message));
        });

        if (report.truncated) {
            warnings.append(
                createElement(
                    "div",
                    "warn",
                    "Too many findings: the scan stopped at the first 5000."
                )
            );
        }

        const typeFilter = $("#type-filter");
        typeFilter.replaceChildren(new Option("All types", "all"));

        Object.entries(report.by_type).forEach(([type, count]) => {
            typeFilter.append(
                new Option(`${type} (${count})`, type)
            );
        });

        document.querySelectorAll(".seg-btn").forEach((button) => {
            button.classList.toggle(
                "active",
                button.dataset.sev === "all"
            );
        });

        drawRows();
    }

    // Display findings that match the selected filters.
    function drawRows() {
        const report = state.report;
        if (!report) return;

        const filteredRows = report.findings.filter((finding) => {
            const matchesSeverity =
                state.severity === "all" ||
                finding.severity === state.severity;

            const matchesType =
                state.type === "all" ||
                finding.label === state.type;

            return matchesSeverity && matchesType;
        });

        const tableBody = $("#rows");
        tableBody.replaceChildren();

        if (!filteredRows.length) {
            const row = createElement("tr");
            const cell = createElement(
                "td",
                "empty",
                report.total
                    ? "No findings match this filter."
                    : "No sensitive data found. This file looks clean."
            );

            cell.colSpan = 5;
            row.append(cell);
            tableBody.append(row);
        }

        filteredRows.slice(0, MAX_ROWS).forEach((finding) => {
            const row = createElement("tr");
            const severityCell = createElement("td");
            const badge = createElement(
                "span",
                `badge ${finding.severity}`,
                finding.severity
            );

            severityCell.append(badge);

            row.append(
                severityCell,
                createElement("td", "", finding.label),
                createElement("td", "", finding.location),
                createElement("td", "mono", finding.masked),
                createElement("td", "mono", finding.context)
            );

            tableBody.append(row);
        });

        $("#more").textContent = filteredRows.length > MAX_ROWS
            ? `Showing the first ${MAX_ROWS} of ${filteredRows.length}. Download the report for all of them.`
            : "";
    }

    // Filter findings by severity.
    document.querySelectorAll(".seg-btn").forEach((button) => {
        button.addEventListener("click", () => {
            state.severity = button.dataset.sev;

            document.querySelectorAll(".seg-btn").forEach((item) => {
                item.classList.toggle("active", item === button);
            });

            drawRows();
        });
    });

    // Filter findings by data type.
    $("#type-filter").addEventListener("change", (event) => {
        state.type = event.target.value;
        drawRows();
    });

    // Download the generated report.
    function downloadFile(filename, content, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = createElement("a");

        link.href = url;
        link.download = filename;
        link.click();

        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // Prevent spreadsheet applications from treating cells as formulas.
    function formatCsvCell(value) {
        let text = String(value);

        if (/^[=+\-@\t\r]/.test(text)) {
            text = "'" + text;
        }

        return `"${text.replace(/"/g, '""')}"`;
    }

    $("#dl-json").addEventListener("click", () => {
        if (!state.report) return;

        downloadFile(
            "sdd-report.json",
            JSON.stringify(state.report, null, 2),
            "application/json"
        );
    });

    $("#dl-csv").addEventListener("click", () => {
        if (!state.report) return;

        const headers = [
            "severity",
            "type",
            "location",
            "masked_value",
            "context"
        ];

        const rows = state.report.findings.map((finding) => [
            finding.severity,
            finding.label,
            finding.location,
            finding.masked,
            finding.context
        ]);

        const csv = [
            headers.join(","),
            ...rows.map((row) => row.map(formatCsvCell).join(","))
        ].join("\n");

        downloadFile("sdd-report.csv", csv, "text/csv");
    });
})();
