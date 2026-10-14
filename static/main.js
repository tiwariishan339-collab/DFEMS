/**
 * DFEMS - Digital Forensic Evidence Management System
 * Interactive UI Engine & Security Tooling
 */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Sidebar Toggle for Mobile Devices
    const sidebar = document.getElementById("sidebar");
    const sidebarToggle = document.getElementById("sidebarToggle");
    const sidebarOverlay = document.getElementById("sidebarOverlay");

    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener("click", () => {
            sidebar.classList.toggle("open");
            if (sidebarOverlay) sidebarOverlay.classList.toggle("active");
        });
    }

    if (sidebarOverlay && sidebar) {
        sidebarOverlay.addEventListener("click", () => {
            sidebar.classList.remove("open");
            sidebarOverlay.classList.remove("active");
        });
    }

    // 2. Drag & Drop File Upload Handling
    const dropZone = document.getElementById("evidenceDropZone");
    const fileInput = document.getElementById("evidenceFileInput");
    const fileInfo = document.getElementById("selectedFileInfo");
    const fileNameDisplay = document.getElementById("selectedFileName");
    const fileSizeDisplay = document.getElementById("selectedFileSize");

    if (dropZone && fileInput) {
        ["dragenter", "dragover"].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.add("dragover");
            }, false);
        });

        ["dragleave", "drop"].forEach(eventName => {
            dropZone.addEventListener(eventName, (e) => {
                e.preventDefault();
                e.stopPropagation();
                dropZone.classList.remove("dragover");
            }, false);
        });

        dropZone.addEventListener("drop", (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileDisplay(files[0]);
            }
        });

        fileInput.addEventListener("change", () => {
            if (fileInput.files.length > 0) {
                updateFileDisplay(fileInput.files[0]);
            }
        });

        function updateFileDisplay(file) {
            if (!fileInfo) return;
            fileInfo.classList.remove("d-none");
            if (fileNameDisplay) fileNameDisplay.textContent = file.name;
            if (fileSizeDisplay) {
                let sizeStr = "";
                const bytes = file.size;
                if (bytes < 1024) sizeStr = bytes + " B";
                else if (bytes < 1048576) sizeStr = (bytes / 1024).toFixed(2) + " KB";
                else sizeStr = (bytes / 1048576).toFixed(2) + " MB";
                fileSizeDisplay.textContent = sizeStr;
            }
        }
    }

    // 3. Verification Spinner on Click
    const verifyButtons = document.querySelectorAll(".btn-verify-action");
    verifyButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const originalHtml = btn.innerHTML;
            btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Computing SHA-256 Checksum...`;
            btn.classList.add("disabled");
        });
    });

    // 4. Form Submit Loading States
    const uploadForm = document.getElementById("evidenceUploadForm");
    if (uploadForm) {
        uploadForm.addEventListener("submit", () => {
            const submitBtn = uploadForm.querySelector("button[type='submit']");
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Securing Evidence & Generating SHA-256...`;
            }
        });
    }
});

/**
 * Copy text to clipboard with visual feedback
 */
function copyToClipboard(text, buttonElement) {
    if (!navigator.clipboard) {
        // Fallback for older browsers
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            triggerCopySuccess(buttonElement);
        } catch (err) {
            console.error('Fallback copy failed: ', err);
        }
        document.body.removeChild(textArea);
        return;
    }

    navigator.clipboard.writeText(text).then(() => {
        triggerCopySuccess(buttonElement);
    }).catch(err => {
        console.error("Could not copy text: ", err);
    });
}

function triggerCopySuccess(buttonElement) {
    if (!buttonElement) return;
    const originalText = buttonElement.innerHTML;
    buttonElement.innerHTML = `<i class="bi bi-check2-circle text-success me-1"></i> Copied!`;
    buttonElement.classList.add("btn-copied");
    setTimeout(() => {
        buttonElement.innerHTML = originalText;
        buttonElement.classList.remove("btn-copied");
    }, 2200);
}
