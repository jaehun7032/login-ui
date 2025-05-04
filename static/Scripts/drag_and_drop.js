$(document).ready(function() {
    var draggedElement = null;
    var items = document.querySelectorAll(".container .box");

    items.forEach(function(item) {
        item.addEventListener("dragstart", handleDragStart);
        item.addEventListener("dragenter", handleDragEnter);
        item.addEventListener("dragover", handleDragOver);
        item.addEventListener("dragleave", handleDragLeave);
        item.addEventListener("drop", handleDrop);
        item.addEventListener("dragend", handleDragEnd);
    });

    function handleDragStart(e) {
        this.style.opacity = "0.4";
        draggedElement = this;
        e.dataTransfer.effectAllowed = "move";
        e.dataTransfer.setData("item", this.innerHTML);
    }
    function handleDragOver(e) {
        if (e.preventDefault) e.preventDefault();
        e.dataTransfer.dropEffect = "move";
        return false;
    }
    function handleDragEnter(e) {
        this.classList.add("dragover");
    }
    function handleDragLeave(e) {
        this.classList.remove("dragover");
    }
    function handleDrop(e) {
        if (e.stopPropagation) e.stopPropagation();
        if (draggedElement !== this) {
            draggedElement.innerHTML = this.innerHTML;
            draggedElement.setAttribute("data-item", this.innerHTML);
            let replacedItem = e.dataTransfer.getData("item");
            this.innerHTML = replacedItem;
            this.setAttribute("data-item", replacedItem);
        }
        return false;
    }
    function handleDragEnd(e) {
        this.style.opacity = "1";
        items.forEach(function(item) {
            item.classList.remove("dragover");
        });
    }
});