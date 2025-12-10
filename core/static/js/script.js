document.addEventListener("DOMContentLoaded", () => {

    console.log("Script Loaded ✓");

    /* --------------------------------------------
       STOP SCRIPT ON NON-DASHBOARD PAGES
    -------------------------------------------- */
    const pendingList = document.getElementById("pendingList");
    const reservationModal = document.getElementById("reservationModal");
    const declinedModal = document.getElementById("declinedModal");

    // If these do NOT exist → STOP script (prevents null errors)
    if (!pendingList || !reservationModal || !declinedModal) {
        console.warn("Dashboard elements missing → Script disabled on this page.");
        return;
    }

    /* ---------------- CSRF TOKEN ---------------- */
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie !== "") {
            document.cookie.split(";").forEach(cookie => {
                cookie = cookie.trim();
                if (cookie.startsWith(name + "=")) {
                    cookieValue = cookie.substring(name.length + 1);
                }
            });
        }
        return cookieValue;
    }
    const csrftoken = getCookie("csrftoken");

    /* ---------------- SAFE TOAST FUNCTION ---------------- */
    function showToast(message, type = "success") {
        let container = document.getElementById("toast-container");

        if (!container) {
            container = document.createElement("div");
            container.id = "toast-container";
            container.style.position = "fixed";
            container.style.top = "20px";
            container.style.right = "20px";
            container.style.zIndex = "99999";
            document.body.appendChild(container);
        }

        const toast = document.createElement("div");
        toast.textContent = message;
        toast.style = `
            padding: 14px 18px;
            border-radius: 8px;
            color: #fff;
            font-size: 0.9rem;
            font-weight: 600;
            box-shadow: 0 4px 10px rgba(0,0,0,0.25);
            opacity: 0;
            transform: translateX(100%);
            transition: opacity .35s ease, transform .35s ease;
        `;

        toast.style.background =
            type === "success" ? "#22c55e" :
            type === "error" ? "#e11d48" : "#3b82f6";

        container.appendChild(toast);

        requestAnimationFrame(() => {
            toast.style.opacity = "1";
            toast.style.transform = "translateX(0)";
        });

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateX(100%)";
            setTimeout(() => toast.remove(), 350);
        }, 3500);
    }

    /* ---------------- FETCH PENDING REQUESTS ---------------- */
    async function fetchPending() {

        const notifCount = document.getElementById("notifCount");

        try {
            const res = await fetch("/api/pending-requests/", { cache: "no-store" });
            const data = await res.json();

            pendingList.innerHTML = data.html || "<li>No pending requests</li>";

            if (notifCount) {
                notifCount.style.display = data.count > 0 ? "inline-flex" : "none";
                notifCount.textContent = data.count;
            }

            attachClickEvents();
        }
        catch (err) {
            console.error("Pending fetch error:", err);
        }
    }

    fetchPending();
    setInterval(fetchPending, 1000);

    /* ---------------- OPEN MODAL & LOAD DETAILS ---------------- */
    function attachClickEvents() {
        const items = document.querySelectorAll(".pending-item");
        if (items.length === 0) return;

        items.forEach(item => {
            const id = item.dataset.id;

            item.onclick = async () => {
                const res = await fetch(`/api/reservation_detail/${id}/`);
                const data = await res.json();

                document.getElementById("modalPriorityBadge").className =
                    "badge " + (data.priority_display === "High" ? "high" : "low");

                document.getElementById("modalPriorityBadge").innerText =
                    data.priority_display;

                document.getElementById("modalBorrower").innerText =
                    data.userborrower?.full_name || "Unknown";

                document.getElementById("modalContact").innerText =
                    data.userborrower?.contact_number || "No contact";

                const list = document.getElementById("modalItemList");
                list.innerHTML = "";
                data.items.forEach(it => {
                    list.innerHTML += `<li><strong>${it.item_name}</strong> — x${it.quantity}</li>`;
                });

                document.getElementById("modalBorrowDate").innerText = data.date_borrowed;
                document.getElementById("modalReturnDate").innerText = data.date_return;
                document.getElementById("modalReasonLeft").innerText = data.message;

                /* ---- DECLINE REASON ---- */
                const declineSection = document.getElementById("declineReasonSection");
                const declineText = document.getElementById("modalDeclineReason");

                if (data.status === "declined" && data.reason) {
                    declineSection.style.display = "block";
                    declineText.innerText = data.reason;
                } else {
                    declineSection.style.display = "none";
                }

                document.getElementById("modalID").src = data.valid_id_image || "";

                reservationModal.style.display = "flex";

                document.getElementById("approveBtn").onclick =
                    () => updateReservation(id, "approved");

                document.getElementById("declinedBtn").onclick = () => {

                    console.log("Decline button clicked");
                    console.log("Showing decline modal...");

                    if (!declinedModal) {
                        console.error("ERROR: declinedModal is NULL! Cannot open modal.");
                        debugger;
                        return;
                    }

                    declinedModal.style.display = "flex";

                    const submitBtn = document.getElementById("submitDecline");
                    const reasonInput = document.getElementById("declinedReason");

                    console.log("submitBtn =", submitBtn);
                    console.log("reasonInput =", reasonInput);

                    if (!submitBtn) {
                        console.error("ERROR: submitDecline button NOT FOUND!");
                        debugger;
                        return;
                    }

                    if (!reasonInput) {
                        console.error("ERROR: declinedReason textarea NOT FOUND!");
                        debugger;
                        return;
                    }

                    submitBtn.onclick = () => {
                        console.log("Submit Decline clicked…");

                        const reason = reasonInput.value.trim();
                        console.log("Entered reason:", reason);

                        if (!reason) {
                            console.error("No reason entered!");
                            return showToast("Please enter a reason!", "error");
                        }

                        console.log("Sending decline update…");
                        updateReservation(id, "declined", reason);
                    };
                };

            };
        });
    }

    /* ---------------- CLOSE MODALS ---------------- */
    document.getElementById("closeModal").onclick =
        () => reservationModal.style.display = "none";

    document.getElementById("cancelDecline").onclick =
        () => declinedModal.style.display = "none";

    /* ---------------- UPDATE RESERVATION ---------------- */
    async function updateReservation(id, status, reason = null) {
        const payload = { status, reason };

        const res = await fetch(`/api/reservation_update/${id}/`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": csrftoken
            },
            body: JSON.stringify(payload)
        });

        const data = await res.json();

        if (data.status === "success") {
            showToast(`Reservation ${status} successfully!`, "success");
            reservationModal.style.display = "none";
            declinedModal.style.display = "none";
            fetchPending();
        } else {
            showToast("Error updating reservation!", "error");
        }
    }

});
