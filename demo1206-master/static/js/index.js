/** !
 *	indexjs
 */

(function() {

    // 侧栏展开折叠
    var sideBar = $(".bk-sidebar");
    $(".slide-switch").on("click", function() {
        sideBar.toggleClass("slide-open slide-close")
        if (sideBar.hasClass("slide-close")) {
            $(".flex-subnavs").hide();
        }
        setTimeout(function() {
            myChart.resize();
        }, 700);
    });

    // 监听分辨率
    $(window).on('resize', function() {
        var width = $(window).width();
        if (width > 1366) {
            sideBar.removeClass("slide-close").addClass("slide-open");

        } else {
            sideBar.removeClass("slide-open").addClass("slide-close");

        }
        setTimeout(function() {
            myChart.resize();
        }, 700);
    });
    $(window).trigger('resize');
})();