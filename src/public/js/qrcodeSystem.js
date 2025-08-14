const qrmodal = document.getElementById("qrmodal");
const video = document.getElementById('qr-video');
const fileSelector = document.getElementById('file-selector');

function scanResult(result) {
    const authkey = document.getElementById('authkey')
    authkey.value = result.data
    manageQrcodeModal(true);

}
function start() {
    const scanner = new QrScanner(video, result => scanResult(result), {
        highlightScanRegion: true,
        highlightCodeOutline: true,
    });

    scanner.start();
}

function manageQrcodeModal(status) {
    qrmodal.hidden = status;
}


function closeModal() {
    qrmodal.hidden = true;
}


function generateQRCode(data) {

    // Clear previous QR code if exists
    const qrcodeElement = document.getElementById('qrcode');
    qrcodeElement.innerHTML = '';

    // Generate new QR code
    const qrCode = new QRCode(qrcodeElement, {
        text: data,
        width: 256,
        height: 256,
        colorDark : "#000000",
        colorLight : "#ffffff",
        correctLevel : QRCode.CorrectLevel.H
    });
}

/**
 * Downloads the generated QR code as a PNG image
 * @param {string} filename - The name of the downloaded file (without extension)
 */

function downloadQRCode(filename = 'AuthQRCode') {
    const login = document.getElementById('login').value;

    // Get the canvas element from the QR code container
    const canvas = document.querySelector('#qrcode canvas');

    if (!canvas) {
        console.error('No QR code found to download');
        return;
    }

    // Convert canvas to data URL
    const dataURL = canvas.toDataURL('image/png');

    // Create a temporary link element
    const downloadLink = document.createElement('a');
    downloadLink.href = dataURL;
    downloadLink.download = `${filename + '_' + login}.png`;

    // Append to the document, click it to trigger download, then remove it
    document.body.appendChild(downloadLink);
    downloadLink.click();
    document.body.removeChild(downloadLink);
}