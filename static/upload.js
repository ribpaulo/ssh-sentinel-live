const dropzone = document.querySelector("#dropzone");
const fileInput = document.querySelector("#log_file");
const fileStatus = document.querySelector("#file-status");

const maximumSize = 2 * 1024 * 1024;
const allowedExtensions = [".log", ".txt"];

function showFile(file, assignToInput = false) {
    dropzone.classList.remove("is-dragging", "has-file", "is-error");

    const extension = file.name.slice(file.name.lastIndexOf(".")).toLowerCase();
    if (!allowedExtensions.includes(extension)) {
        fileInput.value = "";
        fileInput.setCustomValidity("Only .log and .txt files are allowed.");
        fileStatus.textContent = "Unsupported file: use .log or .txt.";
        dropzone.classList.add("is-error");
        return;
    }

    if (file.size > maximumSize) {
        fileInput.value = "";
        fileInput.setCustomValidity("The file must not exceed 2 MB.");
        fileStatus.textContent = "File too large: maximum 2 MB.";
        dropzone.classList.add("is-error");
        return;
    }

    if (assignToInput) {
        const transfer = new DataTransfer();
        transfer.items.add(file);
        fileInput.files = transfer.files;
    }

    fileInput.setCustomValidity("");
    fileStatus.textContent = `${file.name} · ${(file.size / 1024).toFixed(1)} KB`;
    dropzone.classList.add("has-file");
}

fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
        showFile(fileInput.files[0]);
    }
});

["dragenter", "dragover"].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        event.stopPropagation();
        dropzone.classList.add("is-dragging");
    });
});

dropzone.addEventListener("dragleave", (event) => {
    event.preventDefault();
    if (!dropzone.contains(event.relatedTarget)) {
        dropzone.classList.remove("is-dragging");
    }
});

dropzone.addEventListener("drop", (event) => {
    event.preventDefault();
    event.stopPropagation();
    dropzone.classList.remove("is-dragging");

    if (event.dataTransfer.files.length !== 1) {
        fileInput.value = "";
        fileInput.setCustomValidity("Please drop exactly one file.");
        fileStatus.textContent = "Please drop exactly one file.";
        dropzone.classList.remove("has-file");
        dropzone.classList.add("is-error");
        return;
    }

    showFile(event.dataTransfer.files[0], true);
});
